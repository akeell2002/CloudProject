"""Generate reader-friendly Matplotlib PNGs from a completed benchmark run."""
import argparse
import csv
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
INK = "#14243a"
MUTED = "#42556b"
BLUE = "#215ca9"
ORANGE = "#b75014"
TEAL = "#147d71"
TRACK = "#e7edf4"
GRID = "#d8e2ee"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path, help="Path to a run under benchmarks/results")
    parser.add_argument("--threat-tick-step", type=int, choices=(5, 10), default=5)
    args = parser.parse_args()
    run = args.run.resolve()
    if run.parent != HERE / "results" or not (run / "summary.csv").is_file():
        parser.error("Choose a completed run directory under benchmarks/results.")
    os.environ["MPLCONFIGDIR"] = str(run / ".matplotlib")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator, PercentFormatter

    with (run / "summary.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))

    def suite(name):
        return [row for row in rows if row["suite"] == name]

    def canvas(title, subtitle, note, height):
        fig = plt.figure(figsize=(10.8, height), facecolor="white")
        fig.text(0.055, 0.94, title, fontsize=22, weight="bold", color=INK, va="top")
        fig.text(0.055, 0.94 - 0.37 / height, subtitle, fontsize=11, color=MUTED, va="top")
        fig.text(0.055, 0.08, note, fontsize=10, color=MUTED, va="center", linespacing=1.45)
        return fig

    def axis(fig, left=0.23):
        ax = fig.add_axes((left, 0.25, 0.92 - left, 0.48))
        ax.spines[:].set_visible(False)
        ax.set_axisbelow(True)
        ax.grid(axis="x", color=GRID, linewidth=0.8)
        ax.tick_params(length=0, pad=8, labelcolor=MUTED, labelsize=10)
        ax.xaxis.label.set_color(MUTED)
        return ax

    def save(fig, filename):
        fig.savefig(run / filename, dpi=160, facecolor="white")
        plt.close(fig)

    if suite("micro"):
        with (run / "raw.csv").open(newline="", encoding="utf-8") as stream:
            micro = [r for r in csv.DictReader(stream) if r["suite"] == "micro" and r["outcome"] == "ok"]
        fig = canvas("How long did each screening test take?",
                     "Each dot is one timed batch. The two panels use separate time scales.",
                     "Times exclude HTTP. For a time per check, divide the batch time by its number of checks.", 6.2)
        fig.set_figwidth(12)
        for i, (case, title, color, ticks) in enumerate((
            ("firewall", "Blocklist screening", BLUE, range(10, 21)),
            ("classifier", "Threat screening", TEAL, range(800, 901, args.threat_tick_step)),
        )):
            data = sorted((r for r in micro if r["case"] == case), key=lambda r: int(r["trial"]))
            trials = [int(r["trial"]) for r in data]
            times = [int(r["elapsed_ns"]) / 1e6 for r in data]
            counts = {int(r["operations"]) for r in data}
            label = f"per {counts.pop():,} checks" if len(counts) == 1 else "Check counts are in raw.csv"
            ax = fig.add_axes((0.10 + i * 0.46, 0.23, 0.36, 0.46))
            ax.set_title(f"{title} ({label})", color=INK, loc="center", fontsize=13, pad=13)
            ax.spines[:].set_visible(False)
            ax.set_axisbelow(True)
            ax.grid(axis="y", color=GRID, linewidth=0.8)
            ax.tick_params(length=0, pad=5, labelcolor=MUTED)
            ax.set(xlabel="Test number", ylabel="Total batch time (ms)", ylim=(0, max(times) * 1.23))
            if ticks[0] <= min(times) and max(times) <= ticks[-1]:
                ax.set_yticks(ticks)
                ax.set_ylim(ticks[0], ticks[-1])
            ax.xaxis.label.set_color(MUTED)
            ax.yaxis.label.set_color(MUTED)
            ax.plot(trials, times, marker="o", color=color, linewidth=1.7, markersize=6)
            ax.margins(x=0.10)
            if len(trials) <= 15:
                ax.set_xticks(trials)
                for j, (trial, value) in enumerate(zip(trials, times)):
                    offset = -12 if len(trials) > 5 and j % 2 and value != max(times) else 8
                    ax.annotate(f"{value:,.2f}", (trial, value), xytext=(0, offset), textcoords="offset points",
                                ha="center", color=color, fontsize=8 if len(trials) > 10 else 9, weight="bold")
            else:
                ax.xaxis.set_major_locator(MaxNLocator(nbins=8, integer=True))
        filename = "micro.png" if args.threat_tick_step == 5 else "micro-threat-10ms.png"
        save(fig, filename)


    consensus = sorted(suite("consensus"), key=lambda row: int(row["case"]))
    if consensus:
        successful = min(int(r["successes"]) for r in consensus)
        note = "p95 estimates the time within which 95% of successful trials finish."
        if successful < 10:
            note += " With few trials, it can vary widely."
        fig = canvas("How long until the ban takes effect?",
                     "From submitting a flagged post to seeing the ban on all nodes in the test.", note,
                     max(4.0, 2.8 + len(consensus) * 0.57))
        ax = axis(fig)
        maximum = max((float(r[k]) for r in consensus for k in ("mean_ms", "p95_ms") if r[k]), default=1)
        for i, row in enumerate(consensus):
            for key, name, offset, color in (
                ("mean_ms", "Average", -0.18, BLUE), ("p95_ms", "p95", 0.18, ORANGE)
            ):
                if row[key]:
                    value = float(row[key])
                    ax.barh(i + offset, value, height=0.28, color=color)
                    ax.text(value + maximum * 0.022, i + offset, f"{name}  {value:,.1f} ms",
                            va="center", color=color, fontsize=10, weight="bold")
                else:
                    label = "No successful trials" if key == "mean_ms" else "p95 unavailable"
                    ax.text(maximum * 0.022, i + offset, label, va="center", color=MUTED, fontsize=10)
        ax.set(xlim=(0, maximum * 1.29), ylim=(len(consensus) - 0.52, -0.48), xlabel="Time to observe the ban (milliseconds)")
        ax.set_yticks(range(len(consensus)),
                      [f"{r['case']} voting nodes\n{r['successes']} of {r['trials']} succeeded" for r in consensus])
        save(fig, "consensus.png")

    faults = suite("fault")
    if faults:
        labels = {"HONEST": "All nodes vote normally",
                  "LIAR": "One node votes against the ban",
                  "FORGER": "One node is set to forge signatures"}
        fig = canvas("Did the ban still go through?",
                     "Each test starts with five voting nodes. A ban needs four approvals.",
                     "Success means all honest nodes reported the ban before the trial timed out.", 4.5)
        ax = axis(fig, left=0.32)
        for i, row in enumerate(faults):
            total, success = int(row["trials"]), int(row["successes"])
            fraction = success / total
            ax.barh(i, 1, height=0.38, color=TRACK)
            ax.barh(i, fraction, height=0.38, color=TEAL)
            ax.text(fraction + 0.025, i, f"{success} of {total}  ({fraction:.0%})",
                    va="center", fontsize=10, weight="bold", color=INK)
        ax.set(xlim=(0, 1.28), ylim=(len(faults) - 0.5, -0.5), xlabel="Share of trials that succeeded")
        ax.set_xticks([0, 0.25, 0.50, 0.75, 1])
        ax.xaxis.set_major_formatter(PercentFormatter(1))
        ax.set_yticks(range(len(faults)), [labels.get(r["case"], r["case"]) for r in faults])
        save(fig, "faults.png")

    recovery = sorted(suite("recovery"), key=lambda row: int(row["case"]))
    if recovery:
        fig = canvas("How long does replaying missed bans take?",
                     "A recovering node reapplies missed bans using their signed certificates.",
                     "Local replay includes signature checks, saving bans and updating the firewall.\n"
                     "The timer excludes restarting the node and downloading the records.", 5.1)
        ax = axis(fig, left=0.26)
        seconds = [float(row["mean_ms"]) / 1000 for row in recovery]
        bars = ax.barh(range(len(recovery)), seconds, height=0.46, color=BLUE)
        ax.bar_label(bars, [f"{value:.2f} s" for value in seconds],
                     padding=7, color=INK, fontsize=11, weight="bold")
        ax.set(xlim=(0, max(seconds) * 1.21), ylim=(len(recovery) - 0.5, -0.5),
               xlabel="Average time to replay the whole batch (seconds)")
        ax.set_yticks(range(len(recovery)), [f"{int(r['case']):,} missed bans" for r in recovery])
        save(fig, "recovery.png")


if __name__ == "__main__":
    main()
