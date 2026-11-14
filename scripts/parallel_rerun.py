"""Parallel rerun: all six Claude configurations over identical OWASP 400 sample.
Independent model-scanning workers share a per-model adaptive rate controller.
The primary speed measure is complete experiment wall-clock scan duration.
"""
import asyncio
import csv
import json
import math
import os
import random
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from anthropic import AsyncAnthropic, APIStatusError, APIConnectionError
from prepare import REV
from standalone_haiku import SYSTEM as STANDALONE_SYSTEM, TARGET_CWES
from standalone_haiku import prompt as standalone_prompt, parse_answer as parse_standalone
from hybrid_haiku import SYSTEM as HYBRID_SYSTEM, cwes, confusion
from hybrid_haiku import prompt as hybrid_prompt, parse_answer as parse_hybrid

MODELS = {
    "haiku": ("claude-haiku-5-5", 0.1, 0.5, 1.0),
    "sonnet": ("claude-sonnet-5-5", 2.0, 10.0, 5.0),
    "opus": ("claude-opus-5-5", 4.0, 20.0, 8.5),
}
MAX_TOKENS = 4096
ROOT = Path("results/parallel_rerun_400")
SOURCE = Path("benchmark/selected/src/main/java/org/owasp/benchmark/testcode")
SCHEMA_STANDALONE = {"type":"object","properties":{"cwes":{"type":"array","items":{"type":"integer","enum":TARGET_CWES}}},"required":["cwes"],"additionalProperties":False}
SCHEMA_HYBRID = {"type":"object","properties":{"genuine":{"type":"boolean"}},"required":["genuine"],"additionalProperties":False}


def load():
    with Path("results/stratified_sample_400.csv").open(newline="",encoding="utf-8") as f:
        cases = list(csv.DictReader(f))
    if len(cases)!=400 or len({r["test_id"] for r in cases})!=400 or sum(r["vulnerable"]=="true" for r in cases)!=206:
        raise RuntimeError("Unexpected stratified sample")
    texts = {r["test_id"]:(SOURCE/(r["test_id"]+".java")).read_text(encoding="utf-8") for r in cases}
    scan = json.loads(Path("results/sample_400/scan_metadata.json").read_text(encoding="utf-8"))
    raw = json.loads(Path("results/sample_400/semgrep.json").read_text(encoding="utf-8"))
    if scan["exit_code"]!=0 or scan["semgrep_version"]!="1.185.0" or raw.get("errors") or len(raw["results"])!=324:
        raise RuntimeError("Semgrep scan differs from pinned baseline")
    findings=defaultdict(list)
    for f in raw["results"]:
        m=re.search(r"(BenchmarkTest\d{5})\.java$",f.get("path",""))
        if not m or m.group(1) not in texts:
            raise RuntimeError("Finding outside sample")
        findings[m.group(1)].append(f)
    baseline=confusion([(any(int(r["cwe"]) in cwes(f) for f in findings[r["test_id"]]),r["vulnerable"]=="true") for r in cases])
    if (baseline["tp"],baseline["fp"],baseline["fn"],baseline["tn"])!=(166,80,40,114):
        raise RuntimeError("Semgrep confusion matrix changed")
    return cases,texts,findings,scan,baseline


class Throttle:
    def __init__(self):
        self.allowed=4
        self.active=0
        self.cooldown=0.0
        self.successes=0
        self.limits=0
        self.lock=asyncio.Lock()

    async def enter(self):
        while True:
            async with self.lock:
                wait=self.cooldown-time.monotonic()
                if wait<=0 and self.active<self.allowed:
                    self.active+=1
                    return
            await asyncio.sleep(max(0.05,min(1.0,wait)) if wait>0 else 0.05)

    async def leave(self,success=False,rate_delay=None):
        async with self.lock:
            self.active-=1
            if rate_delay is not None:
                self.limits+=1
                self.allowed=max(1,self.allowed//2)
                self.successes=0
                self.cooldown=max(self.cooldown,time.monotonic()+rate_delay)
            elif success:
                self.successes+=1
                if self.successes>=40 and self.allowed<8:
                    self.allowed+=1
                    self.successes=0

def backoff(error,attempt):
    try:
        val=float(getattr(error.response,"headers",{}).get("retry-after",""))
        if math.isfinite(val) and val>=0:
            return min(120.0,val+random.uniform(0.1,0.4))
    except (TypeError,ValueError,AttributeError):
        pass
    return min(60.0,2**min(attempt,6)+random.uniform(0.1,1.0))


class Experiment:
    def __init__(self,mode,tier,cases,texts,findings):
        self.mode=mode
        self.tier=tier
        self.name=mode+"-"+tier
        self.model,self.input_rate,self.output_rate,self.cap=MODELS[tier]
        self.system=STANDALONE_SYSTEM if mode=="standalone" else HYBRID_SYSTEM
        self.schema=SCHEMA_STANDALONE if mode=="standalone" else SCHEMA_HYBRID
        self.tasks=[]
        for row in cases:
            cid=row["test_id"]
            if mode=="standalone":
                self.tasks.append((cid,None,None,standalone_prompt(texts[cid])))
            else:
                for idx,finding in enumerate(findings[cid]):
                    self.tasks.append((cid,idx,finding,hybrid_prompt(finding,texts[cid])))
        self.results=defaultdict(list)
        self.cost=0.0
        self.reserved=0.0
        self.tokens_in=self.tokens_out=0
        self.calls=self.retries=self.invalid=self.api_errors=self.rate_limits=0
        self.request_seconds=0.0
        self.thinking=0
        self.thinking_observations=0
        self.error=None
        self.lock=asyncio.Lock()
        self.path=ROOT/self.name
        self.path.mkdir(parents=True,exist_ok=True)
        self.log=(self.path/"requests.jsonl").open("w",encoding="utf-8")

    def predicted_upper_usd(self,prompt):
        # Conservative in-flight cost reservation; not a provider billing limit.
        input_bound=len(prompt.encode("utf-8"))+len(self.system.encode("utf-8"))+2048
        return (input_bound*self.input_rate+MAX_TOKENS*self.output_rate)/1e6

    async def book(self,usd):
        async with self.lock:
            if self.error:
                return False
            if self.cost+self.reserved+usd>self.cap:
                self.error="Budget guard reached before completing all cases"
                return False
            self.reserved+=usd
            return True

    async def unbook(self,usd):
        async with self.lock:
            self.reserved-=usd

    async def write(self,record,usage=None,duration=None):
        async with self.lock:
            if usage is not None:
                i,o=int(usage.input_tokens),int(usage.output_tokens)
                usd=(i*self.input_rate+o*self.output_rate)/1e6
                self.cost+=usd
                self.tokens_in+=i
                self.tokens_out+=o
                self.calls+=1
                self.request_seconds+=duration
                details=getattr(usage,"output_tokens_details",None)
                thoughts=getattr(details,"thinking_tokens",None)
                if thoughts is not None:
                    self.thinking+=thoughts
                    self.thinking_observations+=1
                record.update({"input_tokens":i,"output_tokens":o,"thinking_tokens":thoughts,"cost_usd":round(usd,9),"request_seconds":round(duration,5)})
            self.log.write(json.dumps(record)+"\n")
            self.log.flush()


async def evaluate_one(exp,item,client,throttle):
    cid,index,finding,text=item
    reserve=exp.predicted_upper_usd(text)
    if not await exp.book(reserve):
        return
    try:
        for attempt in range(1,11):
            if exp.error:
                return
            await throttle.enter()
            started=time.perf_counter()
            try:
                msg=await client.messages.create(
                    model=exp.model,max_tokens=MAX_TOKENS,system=exp.system,
                    messages=[{"role":"user","content":text}],
                    output_config={"format":{"type":"json_schema","schema":exp.schema}},
                )
            except (APIStatusError,APIConnectionError) as error:
                seconds=time.perf_counter()-started
                status=getattr(error,"status_code",None)
                delay=backoff(error,attempt)
                await throttle.leave(rate_delay=delay if status==429 else None)
                exp.api_errors+=1
                if status==429:
                    exp.rate_limits+=1
                await exp.write({"test_id":cid,"finding_index":index,"attempt":attempt,"error":type(error).__name__,"status":status,"seconds":round(seconds,5),"retry_after_seconds":delay,"note":"No usage returned for failed HTTP attempt"})
                retryable=isinstance(error,APIConnectionError) or status in (429,500,502,503,504,529)
                if not retryable or attempt==10:
                    exp.error=f"{cid}: API failed with {type(error).__name__}, status {status}"
                    return
                exp.retries+=1
                await asyncio.sleep(delay)
                continue
            except Exception as error:
                await throttle.leave()
                exp.error=f"{cid}: unexpected API failure: {type(error).__name__}: {str(error)[:180]}"
                return
            seconds=time.perf_counter()-started
            await throttle.leave(success=True)
            try:
                decision=parse_standalone(msg) if exp.mode=="standalone" else parse_hybrid(msg)
                parse_error=None
            except Exception as error:
                decision=None
                parse_error=f"{type(error).__name__}: {str(error)[:150]}"
                exp.invalid+=1
            await exp.write({"test_id":cid,"finding_index":index,"attempt":attempt,"model":msg.model,"stop_reason":msg.stop_reason,"rule":finding.get("check_id") if finding else None,"reported_cwes":cwes(finding) if finding else None,"detected_cwes":decision if exp.mode=="standalone" else None,"genuine":decision if exp.mode=="hybrid" else None,"parse_error":parse_error},msg.usage,seconds)
            if decision is not None:
                exp.results[cid].append((finding,decision))
                return
            if attempt==10:
                exp.error=f"{cid}: 10 unparseable responses"
                return
            exp.retries+=1
            await asyncio.sleep(0.5)
    finally:
        await exp.unbook(reserve)


async def run_experiment(exp,client,throttle,cases,scan_seconds):
    queue=asyncio.Queue()
    for task in exp.tasks:
        queue.put_nowait(task)
    async def worker():
        while not exp.error:
            try:
                item=queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                await evaluate_one(exp,item,client,throttle)
            except Exception as e:
                exp.error=f"Unhandled worker error: {type(e).__name__}: {str(e)[:200]}"
            finally:
                queue.task_done()
    begin=time.perf_counter()
    await asyncio.gather(*(worker() for _ in range(8)))
    elapsed=time.perf_counter()-begin
    exp.log.close()
    answered=sum(map(len,exp.results.values()))
    complete=not exp.error and answered==len(exp.tasks)
    outcome=[]
    for r in cases:
        cid,cwe=r["test_id"],int(r["cwe"])
        detections=exp.results.get(cid,[])
        prediction=(bool(detections and cwe in detections[0][1]) if exp.mode=="standalone"
                    else any(genuine and cwe in cwes(f) for f,genuine in detections))
        outcome.append({"test_id":cid,"category":r["category"],"truth":r["vulnerable"]=="true","expected_cwe":cwe,"predicted":prediction})
    if complete:
        with (exp.path/"case_predictions.jsonl").open("w",encoding="utf-8") as file:
            for r in outcome:
                file.write(json.dumps(r)+"\n")
    result={
        "complete":bool(complete),"error":exp.error,"configuration":exp.name,
        "model":exp.model,"sample_size":400,"sample_seed":20261114,"benchmark_revision":REV,
        "prompt_type":exp.mode,"response_format":"JSON schema (identical format for all models)",
        "expected_classifications":len(exp.tasks),"completed_classifications":answered,
        "api_requests_with_usage":exp.calls,"api_errors_without_usage":exp.api_errors,
        "rate_limit_events":exp.rate_limits,"retries":exp.retries,"invalid_responses":exp.invalid,
        "input_tokens":exp.tokens_in,"output_tokens":exp.tokens_out,
        "thinking_tokens_reported":exp.thinking if exp.thinking_observations else None,
        "thinking_token_observations":exp.thinking_observations,
        "api_cost_usd":round(exp.cost,9),"cost_guard_usd":exp.cap,
        "inference_wall_seconds":round(elapsed,4),
        "semgrep_scan_seconds":round(scan_seconds if exp.mode=="hybrid" else 0.0,4),
        "total_scan_wall_seconds":round(elapsed+(scan_seconds if exp.mode=="hybrid" else 0.0),4),
        "sum_api_request_seconds_diagnostic":round(exp.request_seconds,4),
        "model_rate_limit_state":{"final_max_in_flight":throttle.allowed,"max_allowed":8,"model_429_events":throttle.limits},
        "metrics":confusion([(x["predicted"],x["truth"]) for x in outcome]) if complete else None,
        "timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "scoring":"Case-level exact OWASP CWE match. Ground truth withheld from all prompts.",
        "timing":"Wall clock includes all API latency, model processing, rate-limit delays and retry time. Excludes environment/setup. Hybrid includes Semgrep scan duration.",
        "limitations":["Provider does not expose pure reasoning duration separately.","All six Claude configurations share model-tier rate limits, so runs compete for throughput.","Cost guards are application-side, not provider billing limits."],
    }
    (exp.path/"summary.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print("FINISHED",exp.name,"complete",complete,"USD",round(exp.cost,6),"wall_sec",round(elapsed,2),"429s",exp.rate_limits,flush=True)
    return result


async def main():
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise RuntimeError("Missing GitHub secret ANTHROPIC_API_KEY")
    cases,texts,findings,scan,baseline=load()
    ROOT.mkdir(parents=True,exist_ok=True)
    throttles={tier:Throttle() for tier in MODELS}
    experiments=[Experiment(mode,tier,cases,texts,findings) for tier in MODELS for mode in ("standalone","hybrid")]
    client=AsyncAnthropic(timeout=120,max_retries=0)
    started=time.perf_counter()
    try:
        responses=await asyncio.gather(*(run_experiment(e,client,throttles[e.tier],cases,scan["scan_seconds"]) for e in experiments))
    finally:
        await client.close()
    overall=time.perf_counter()-started
    combined={
        "complete":all(r["complete"] for r in responses),
        "sample_size":400,"sample_seed":20261114,"benchmark_revision":REV,
        "semgrep_baseline":{"metrics":baseline,"scan_seconds":scan["scan_seconds"],"version":scan["semgrep_version"],"ruleset":scan["ruleset"]},
        "configurations":responses,
        "all_six_parallel_wall_seconds":round(overall,4),
        "all_seven_with_semgrep_wall_seconds":round(overall+scan["scan_seconds"],4),
        "total_successful_api_usage_cost_usd":round(sum(r["api_cost_usd"] for r in responses),8),
        "timestamp_utc":datetime.now(timezone.utc).isoformat(),
    }
    (ROOT/"combined_summary.json").write_text(json.dumps(combined,indent=2)+"\n",encoding="utf-8")
    print("=== COMPLETE PARALLEL RERUN RESULTS ===",flush=True)
    print(json.dumps(combined,indent=2),flush=True)
    if not combined["complete"]:
        raise RuntimeError("At least one model configuration failed")

if __name__=="__main__":
    asyncio.run(main())
