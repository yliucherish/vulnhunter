"""HTML 扫描报告生成。"""
import html
import os
from datetime import datetime

from .detectors.base import Vulnerability

SEVERITY_COLOR = {"high": "#e74c3c", "medium": "#e67e22", "low": "#3498db"}


def generate(vulns: list[Vulnerability], target: str, out_path: str,
             stats: dict | None = None):
    """生成 HTML 报告。stats 为引擎运行统计（覆盖率/失败数），
    如实呈现"哪些注入点因目标无响应未完成检测"——扫描器不假装扫过了。"""
    rows = ""
    for i, v in enumerate(vulns, 1):
        color = SEVERITY_COLOR.get(v.severity, "#999")
        rows += f"""
        <div class="vuln">
          <h3>#{i} {html.escape(v.vuln_type)}
            <span class="sev" style="background:{color}">{v.severity.upper()}</span></h3>
          <table>
            <tr><th>URL</th><td>{html.escape(v.url)}</td></tr>
            <tr><th>参数</th><td><code>{html.escape(v.param)}</code></td></tr>
            <tr><th>Payload</th><td><code>{html.escape(v.payload)}</code></td></tr>
            <tr><th>判定依据</th><td>{html.escape(v.evidence)}</td></tr>
            <tr><th>修复建议</th><td>{html.escape(v.suggestion)}</td></tr>
          </table>
        </div>"""

    # 运行统计区块：如实呈现覆盖率与失败情况
    stats_html = ""
    if stats:
        total_jobs = stats.get("points", 0) * 4  # 4 个检测器
        warn = ('<span class="warn">⚠ 已触发熔断：目标可能不可用或过载，'
                '剩余注入点未完成检测，本次结果不完整</span>'
                if stats.get("tripped") else "")
        slow_note = (f'｜ 慢端点 <b>{stats.get("slow_points", 0)}</b> 个'
                     f'（单次请求过慢，已转入串行通道）'
                     if stats.get("slow_points") else "")
        stats_html = f"""<div class="stats">
  爬取页面 <b>{stats.get('pages', 0)}</b> ｜ 注入点 <b>{stats.get('points', 0)}</b> ｜
  完成检测 <b>{stats.get('completed', 0)}/{total_jobs}</b> ｜
  请求失败 <b>{stats.get('fetch_failures', 0)}</b> 次 {slow_note} {warn}
</div>"""

    page = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>VulnHunter 扫描报告 - {html.escape(target)}</title>
<style>
  body {{ font-family: "Segoe UI", sans-serif; background:#0f1620; color:#e6edf3;
         max-width:900px; margin:40px auto; padding:0 20px; }}
  h1 {{ color:#5b8cff; }} h3 {{ color:#cdd9e5; }}
  .meta {{ color:#8b98a5; margin-bottom:30px; }}
  .stats {{ background:#1a2332; border:1px solid #2d3a4d; border-radius:10px;
            padding:12px 20px; margin-bottom:20px; font-size:14px; }}
  .stats b {{ color:#5b8cff; }}
  .warn {{ color:#f0a35e; }}
  .vuln {{ background:#1a2332; border:1px solid #2d3a4d; border-radius:10px;
           padding:16px 20px; margin-bottom:16px; }}
  .sev {{ font-size:12px; color:#fff; border-radius:4px; padding:2px 8px; vertical-align:middle; }}
  table {{ width:100%; border-collapse:collapse; font-size:14px; }}
  th {{ text-align:left; width:90px; color:#8b98a5; padding:4px; vertical-align:top; }}
  td {{ padding:4px; word-break:break-all; }}
  code {{ background:#0d1117; padding:2px 6px; border-radius:4px; color:#a78bfa; }}
</style></head><body>
<h1>VulnHunter 扫描报告</h1>
<p class="meta">目标: {html.escape(target)} | 时间: {datetime.now():%Y-%m-%d %H:%M:%S} |
共发现 <b>{len(vulns)}</b> 个漏洞</p>
{stats_html}
{rows or "<p>未发现漏洞。</p>"}
</body></html>"""

    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)
    return out_path
