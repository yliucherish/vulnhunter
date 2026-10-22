"""时间型盲注的公共判定逻辑（SQL 时间盲注与命令注入共用）。

设计要点（面试可讲）：
- 时间型检测是所有"无回显漏洞"的通用手段，但极易受并发噪声干扰——
  并发扫描时其他请求会拖慢目标，让个别响应"看起来变慢"。
- 本模块用三道防线把误报压到最低：
  1. 基线请求 **3 次取中位数**（不是平均值，抵抗单次毛刺）；
  2. **双时长差值判定**：分别注入 sleep(3) 与 sleep(6)，要求两者都慢
     且**耗时差与时长差成比例**（t6 - t3 > 1.5s）。并发负载会同等拖慢
     两个请求，但拖不出"差值"——这是区分"真延迟"与"系统忙"的关键；
  3. **换序复验**：疑似命中后反序再测一轮（6→3），结果仍成立才算数。
- 踩坑记录：初版只做"退避 1 秒再测一次"，结果在 DVWA 扫描中依然误报——
  因为复验期间同一批并发任务还在打目标站。差值法才是正解。
"""
import asyncio
import statistics
import time

from ._http import fetch_with

BASELINE_RUNS = 3            # 基线取中位数，抗网络抖动
SLEEP_PAIR = (3, 5)          # 双时长对：短/长（总等待约 16s/点，兼顾检出与耗时）
TIME_THRESHOLD = 2.0         # 单次超阈值判定
DIFF_THRESHOLD = 1.5         # 长短耗时差下限（抗并发系统性负载）


async def detect_time_based(session, point, make_payload, sleep_pair: tuple = SLEEP_PAIR):
    """对注入点做时间型检测。

    Args:
        make_payload: 由调用方提供，输入 sleep 秒数，返回完整注入 payload。
                       这样 SQL（SLEEP）与命令注入（sleep）可复用同一判别逻辑。

    Returns:
        (payload, evidence) 命中；None 未命中。
    """
    async def measure(payload: str) -> float:
        start = time.perf_counter()
        await fetch_with(session, point, payload)
        return time.perf_counter() - start

    payloads = {sec: make_payload(sec) for sec in sleep_pair}

    async def one_round(order):
        """一轮测量：先测基线，再按 order 依次注入各时长，返回是否成立及明细。"""
        baseline = statistics.median([await measure("test") for _ in range(BASELINE_RUNS)])
        times = {}
        for sec in order:
            times[sec] = await measure(payloads[sec])
        short, long = sleep_pair
        ok = (times[short] - baseline > TIME_THRESHOLD
              and times[long] - baseline > TIME_THRESHOLD
              and times[long] - times[short] > DIFF_THRESHOLD)
        return ok, baseline, times

    # 第一轮（短→长）
    ok, baseline, times = await one_round(sleep_pair)
    if not ok:
        return None

    # 疑似命中 → 换序复验（长→短），进一步排除偶发
    await asyncio.sleep(1.0)
    ok2, baseline2, times2 = await one_round(tuple(reversed(sleep_pair)))
    if not ok2:
        return None

    evidence = (f"注入 sleep({sleep_pair[0]})/sleep({sleep_pair[1]}) 两轮测量："
                f"第一轮耗时 {times[sleep_pair[0]]:.2f}s/{times[sleep_pair[1]]:.2f}s"
                f"（基线 {baseline:.2f}s），第二轮 {times2[sleep_pair[0]]:.2f}s/"
                f"{times2[sleep_pair[1]]:.2f}s（基线 {baseline2:.2f}s），"
                f"长短差值两轮均 >{DIFF_THRESHOLD}s，与注入时长成比例")
    return payloads[sleep_pair[1]], evidence
