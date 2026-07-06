import type { ScoreBreakdown } from "@/lib/types";

// A meter: one ratio (score / 100) against a limit. The arc fill carries state
// via the status ramp (good → warning → serious → critical); the unfilled track
// is a muted step of the same idea. The number itself is the hero figure.

function scoreColor(score: number): string {
  if (score >= 88) return "#0ca30c"; // good
  if (score >= 75) return "#fab219"; // warning
  if (score >= 50) return "#ec835a"; // serious
  return "#d03b3b"; // critical
}

export function ScoreGauge({ score }: { score: ScoreBreakdown }) {
  const color = scoreColor(score.score);
  const size = 180;
  const stroke = 14;
  const r = (size - stroke) / 2;
  const cx = size / 2;
  const cy = size / 2;

  // 270° arc (gap at the bottom), starting from lower-left going clockwise.
  const startAngle = 135;
  const sweep = 270;
  const circumference = 2 * Math.PI * r;
  const arcLength = (sweep / 360) * circumference;
  const filled = (score.score / 100) * arcLength;

  const polar = (angleDeg: number) => {
    const a = (angleDeg * Math.PI) / 180;
    return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
  };
  const start = polar(startAngle);
  const end = polar(startAngle + sweep);
  const largeArc = sweep > 180 ? 1 : 0;
  const arcPath = `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 1 ${end.x} ${end.y}`;

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          role="img"
          aria-label={`Security score ${score.score} out of 100, grade ${score.grade}`}
        >
          {/* Track */}
          <path
            d={arcPath}
            fill="none"
            stroke="rgba(255,255,255,0.09)"
            strokeWidth={stroke}
            strokeLinecap="round"
          />
          {/* Fill */}
          <path
            className="gauge-arc"
            d={arcPath}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${filled} ${arcLength}`}
            style={{ ["--gauge-track" as string]: `${arcLength}` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="text-5xl font-semibold leading-none"
            style={{ color, fontVariantNumeric: "normal" }}
          >
            {score.score}
          </span>
          <span className="mt-1 text-xs uppercase tracking-wider text-[var(--color-muted)]">
            out of 100
          </span>
        </div>
      </div>
      <div className="mt-1 flex items-center gap-2">
        <span
          className="flex h-8 w-8 items-center justify-center rounded-lg text-base font-bold"
          style={{ color, backgroundColor: `${color}20`, border: `1px solid ${color}55` }}
        >
          {score.grade}
        </span>
        <span className="text-sm text-[var(--color-ink-2)]">Security grade</span>
      </div>
    </div>
  );
}
