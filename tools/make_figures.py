"""Render the figures used in the case write-ups, in a light and a dark variant.

The README files pick the variant with <picture> and prefers-color-scheme. Every figure has a table
with the same numbers next to it in the write-up, so no value depends on reading colours.

Usage:
    python tools/make_figures.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from beacon_score import THRESHOLD, load_pairs  # noqa: E402
from evaluate_beacons import beacon_pairs  # noqa: E402

THEMES = {
    "light": {"surface": "#fcfcfb", "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#898781", "grid": "#e1e0d9",
              "axis": "#c3c2b7", "s1": "#2a78d6", "s2": "#eb6834", "s3": "#1baf7a"},
    "dark": {"surface": "#1a1a19", "ink": "#ffffff", "ink2": "#c3c2b7", "muted": "#898781", "grid": "#2c2c2a",
             "axis": "#383835", "s1": "#3987e5", "s2": "#d95926", "s3": "#199e70"},
}
FONT = ["Segoe UI", "DejaVu Sans", "sans-serif"]
for _f in ("segoeui.ttf", "seguisb.ttf", "segoeuib.ttf"):  # system sans on Windows; DejaVu Sans elsewhere
    if (Path("C:/Windows/Fonts") / _f).exists():
        matplotlib.font_manager.fontManager.addfont(str(Path("C:/Windows/Fonts") / _f))
thousands = FuncFormatter(lambda v, _: f"{v:,.0f}")


def style(ax, t, grid_axis="y"):
    ax.set_facecolor(t["surface"])
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(t["axis"])
        ax.spines[side].set_linewidth(0.8)
    ax.tick_params(colors=t["muted"], labelcolor=t["ink2"], labelsize=9, length=0, pad=6)
    ax.grid(axis=grid_axis, color=t["grid"], linewidth=0.8, linestyle="-")
    ax.set_axisbelow(True)


def new_figure(t, w=8.0, h=4.6, **kw):
    plt.rcParams.update({"font.family": FONT, "text.color": t["ink"], "axes.labelcolor": t["ink2"],
                         "axes.labelsize": 9.5})
    fig, axes = plt.subplots(figsize=(w, h), facecolor=t["surface"], **kw)
    return fig, axes


def title(fig, t, main, sub):
    fig.text(0.012, 0.975, main, fontsize=12.5, fontweight="bold", color=t["ink"], va="top")
    fig.text(0.012, 0.925, sub, fontsize=9.5, color=t["ink2"], va="top")


def save(fig, out: Path, name: str, mode: str):
    out.mkdir(parents=True, exist_ok=True)
    fig.savefig(out / f"{name}_{mode}.png", dpi=200, facecolor=fig.get_facecolor())
    plt.close(fig)


# --------------------------------------------------------------------------------------------- case 1

def dns_pairs():
    tunnel_file = ROOT / "_private/zeek/dnscat2_dns_tunneling_24hr/dns_profile.json"
    normal_files = sorted((ROOT / "_private/zeek_published").glob("*_dns_profile.json"))
    tunnel = json.loads(tunnel_file.read_text(encoding="utf-8"))["pairs"]
    normal = [p for f in normal_files for p in json.loads(f.read_text(encoding="utf-8"))["pairs"]]
    normal += [p for p in tunnel if not p["flagged"]]  # the capture's own background traffic
    tunnel = [p for p in tunnel if p["flagged"]]
    return tunnel, normal


def fig_dns_space(out: Path):
    tunnel, normal = dns_pairs()
    normal = [p for p in normal if p["peak_hour_unique_subdomains"] > 0]
    for mode, t in THEMES.items():
        fig, ax = new_figure(t, 8.0, 4.8)
        fig.subplots_adjust(left=0.09, right=0.97, top=0.80, bottom=0.13)
        style(ax, t, grid_axis="both")
        ax.set_yscale("log")
        ax.scatter([p["mean_subdomain_len"] for p in normal], [p["peak_hour_unique_subdomains"] for p in normal],
                   s=34, color=t["s1"], edgecolor=t["surface"], linewidth=1.2, alpha=0.9, zorder=3,
                   label=f"Normal traffic ({len(normal)} client/domain pairs)")
        ax.scatter([p["mean_subdomain_len"] for p in tunnel], [p["peak_hour_unique_subdomains"] for p in tunnel],
                   s=90, marker="D", color=t["s2"], edgecolor=t["surface"], linewidth=1.5, zorder=4,
                   label="dnscat2 tunnel")
        ax.axvline(20, color=t["muted"], linewidth=0.9, zorder=2)
        ax.axhline(50, color=t["muted"], linewidth=0.9, zorder=2)
        ax.text(20.4, 12500, "mean length ≥ 20", color=t["ink2"], fontsize=8.5, va="top")
        ax.text(0.6, 58, "≥ 50 unique subdomains / hour", color=t["ink2"], fontsize=8.5)
        tp = tunnel[0]
        ax.annotate(f"{tp['base_domain']}\n{tp['peak_hour_unique_subdomains']:,} unique subdomains / hour",
                    (tp["mean_subdomain_len"], tp["peak_hour_unique_subdomains"]), xytext=(16, -34),
                    textcoords="offset points", ha="left", fontsize=8.5, color=t["ink"],
                    arrowprops={"arrowstyle": "-", "color": t["muted"], "linewidth": 0.8})
        top = max(normal, key=lambda p: p["peak_hour_unique_subdomains"])
        ax.annotate(f"closest normal: {top['base_domain']} ({top['peak_hour_unique_subdomains']}/h)",
                    (top["mean_subdomain_len"], top["peak_hour_unique_subdomains"]), xytext=(10, 14),
                    textcoords="offset points", fontsize=8.5, color=t["ink2"],
                    arrowprops={"arrowstyle": "-", "color": t["muted"], "linewidth": 0.8})
        ax.set_xlabel("Mean subdomain length (characters)")
        ax.set_ylabel("Peak unique subdomains in one hour")
        ax.yaxis.set_major_formatter(thousands)
        ax.set_xlim(0, max(p["mean_subdomain_len"] for p in normal + tunnel) + 4)
        ax.set_ylim(0.8, 20000)
        ax.legend(loc="center right", frameon=False, fontsize=8.5, labelcolor=t["ink2"])
        title(fig, t, "A DNS tunnel sits alone in the detection space",
              "Every client/base-domain pair in the dnscat2 capture and in 216 h of normal lab traffic "
              "(pairs without subdomains omitted)")
        save(fig, out, "dns_detection_space", mode)


# --------------------------------------------------------------------------------------------- case 2

HIST_SETS = [("jit_var_d30_j0", 0), ("jit_var_d30_j10", 10), ("delay_var_d30_j25", 25), ("jit_var_d30_j99", 99)]


def beacon_gaps(name: str) -> list[float]:
    cap = ROOT / "_private/zeek_published" / name
    truth = beacon_pairs(cap)
    pairs, _ = load_pairs(cap)
    times = sorted(t for k, (ts, _) in pairs.items() if (k[0], k[1], k[2]) in truth for t in ts)
    return [b - a for a, b in zip(times, times[1:])]


def fig_beacon_gaps(out: Path):
    data = [(j, beacon_gaps(n)) for n, j in HIST_SETS]
    for mode, t in THEMES.items():
        fig, axes = new_figure(t, 8.4, 4.9, nrows=2, ncols=2, sharex=True)
        fig.subplots_adjust(left=0.08, right=0.98, top=0.80, bottom=0.11, hspace=0.42, wspace=0.16)
        for ax, (j, gaps) in zip(axes.flat, data):
            style(ax, t)
            gaps = [g for g in gaps if g <= 40]
            ax.hist(gaps, bins=[i * 0.5 for i in range(0, 81)], color=t["s1"], edgecolor=t["surface"],
                    linewidth=0.6, zorder=3)
            lo = 30 * (1 - j / 100)
            ax.set_title(f"jitter {j} %   (expected range {lo:.1f}–30 s)", fontsize=9.5, color=t["ink"],
                         loc="left", pad=6)
            ax.yaxis.set_major_formatter(thousands)
            ax.set_xlim(0, 40)
        for ax in axes[1]:
            ax.set_xlabel("Seconds between check-ins")
        for ax in axes[:, 0]:
            ax.set_ylabel("Check-ins")
        title(fig, t, "Jitter spreads the check-ins but keeps them symmetric",
              "Cobalt Strike HTTP beacon, 30 s delay, 24 h per panel: gaps fall uniformly between "
              "D·(1 − j) and D")
        save(fig, out, "beacon_gap_histograms", mode)


def fig_dispersion_theory(out: Path):
    measured = []
    for name, j in HIST_SETS:
        gaps = sorted(beacon_gaps(name))
        med = gaps[len(gaps) // 2]
        mad = sorted(abs(g - med) for g in gaps)[len(gaps) // 2]
        measured.append((j, 1 - mad / med))
    xs = [i / 100 for i in range(0, 101)]
    theory = [1 - (x / (2 * (2 - x))) for x in xs]
    for mode, t in THEMES.items():
        fig, ax = new_figure(t, 7.2, 4.2)
        fig.subplots_adjust(left=0.10, right=0.96, top=0.78, bottom=0.14)
        style(ax, t, grid_axis="both")
        ax.plot([x * 100 for x in xs], theory, color=t["s1"], linewidth=1.8, zorder=3,
                label="Theory: 1 − j / (2·(2 − j)) for uniform jitter")
        ax.scatter([m[0] for m in measured], [m[1] for m in measured], s=70, marker="D", color=t["s2"],
                   edgecolor=t["surface"], linewidth=1.5, zorder=4, label="Measured on the captures")
        for j, v in measured:
            ax.annotate(f"{v:.3f}", (j, v), xytext=(0, 9), textcoords="offset points", ha="center",
                        fontsize=8.5, color=t["ink2"])
        ax.set_xlabel("Jitter (% of the delay)")
        ax.set_ylabel("Timing-regularity sub-score S_disp")
        ax.set_xlim(-3, 103)
        ax.set_ylim(0.4, 1.05)
        ax.legend(loc="lower left", frameon=False, fontsize=8.5, labelcolor=t["ink2"])
        title(fig, t, "The regularity loss from jitter is predictable",
              "Robust dispersion (MAD / median) of a uniform jitter window, predicted and measured")
        save(fig, out, "beacon_dispersion_theory", mode)


def fig_beacon_scores(out: Path):
    res = json.loads((ROOT / "results/beaconing/evaluation.json").read_text(encoding="utf-8"))
    rows = []
    for r in res:
        rot = {"none": "", "random, 2 redirectors": ", random rotation",
               "round robin, 2 redirectors": ", round robin"}[r["rotation"]]
        label = f"D {r['delay_s']} s, jitter {r['jitter_pct']} %{rot}"
        pair = max(r["pair"]["allowlist"]["beacon_scores"], default=0)
        chan = max(r["channel"]["allowlist"]["beacon_scores"], default=0)
        neg = r["channel"]["allowlist"]["top_negative"]["score"] if r["channel"]["allowlist"]["top_negative"] else 0
        rows.append((label, pair, chan, neg))
    rows = rows[::-1]
    for mode, t in THEMES.items():
        fig, ax = new_figure(t, 8.4, 5.4)
        fig.subplots_adjust(left=0.34, right=0.97, top=0.76, bottom=0.11)
        style(ax, t, grid_axis="x")
        y = list(range(len(rows)))
        # Dodged rows: the three marks of a capture never hide each other when their values coincide.
        ax.scatter([r[3] for r in rows], [v + 0.22 for v in y], s=44, marker="o", color=t["s3"],
                   edgecolor=t["surface"], linewidth=1.2, zorder=3, label="Highest-scoring benign unit")
        ax.scatter([r[1] for r in rows], y, s=44, marker="s", color=t["s1"], edgecolor=t["surface"],
                   linewidth=1.2, zorder=4, label="Beacon, pair mode")
        ax.scatter([r[2] for r in rows], [v - 0.22 for v in y], s=62, marker="D", color=t["s2"],
                   edgecolor=t["surface"], linewidth=1.5, zorder=5, label="Beacon, channel mode")
        ax.axvline(THRESHOLD, color=t["muted"], linewidth=0.9, zorder=2)
        ax.text(THRESHOLD - 0.004, -0.75, f"threshold {THRESHOLD:.2f}", fontsize=8.5, color=t["ink2"], ha="right")
        ax.set_yticks(y, [r[0] for r in rows])
        ax.set_ylim(-0.9, len(rows) - 0.5)
        ax.set_xlim(0.5, 1.02)
        ax.set_xlabel("Beacon score (mean of the four sub-scores)")
        fig.legend(loc="upper left", bbox_to_anchor=(0.34, 0.885), ncol=3, frameon=False, fontsize=8.5,
                   labelcolor=t["ink2"], handletextpad=0.3, columnspacing=1.4)
        title(fig, t, "Merging redirectors recovers the rotated beacons",
              "Best score of the Cobalt Strike beacon per capture, after the a-priori allowlist")
        save(fig, out, "beacon_scores", mode)


def main():
    fig_dns_space(ROOT / "cases/01-dns-tunnel/figures")
    fig_beacon_gaps(ROOT / "cases/02-c2-beaconing/figures")
    fig_dispersion_theory(ROOT / "cases/02-c2-beaconing/figures")
    fig_beacon_scores(ROOT / "cases/02-c2-beaconing/figures")
    print("figures written")


if __name__ == "__main__":
    main()
