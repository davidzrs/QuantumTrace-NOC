import { useCallback, useEffect, useRef, useState } from "react";

const PALETTE = ["#ff5d52", "#f2b441", "#43d1b1"];
const GRID = 48;
const GLOWS = 10;

const reducedMotion = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;

/**
 * Grid background with risk-coloured glows drifting between intersections. Sized to its
 * container, crisp on high-DPI screens, paused while off-screen, and a still frame when the
 * viewer prefers reduced motion..
 */
export function HeroGlow({ opacity = 0.5 }: { opacity?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const c = ref.current;
    const ctx = c?.getContext("2d");
    if (!c || !ctx) return;
    const still = reducedMotion();
    let W = 0;
    let H = 0;
    let frame = 0;
    let visible = true;
    type Glow = { x: number; y: number; tx: number; ty: number; r: number; speed: number; ci: number; a: number };
    let glows: Glow[] = [];

    const snap = (max: number) => Math.floor(Math.random() * (max / GRID + 1)) * GRID;
    const make = (): Glow => ({
      x: snap(W), y: snap(H), tx: snap(W), ty: snap(H),
      r: Math.random() * 80 + 40, speed: Math.random() * 0.015 + 0.01,
      ci: Math.floor(Math.random() * PALETTE.length), a: still ? 1 : 0,
    });

    const draw = (move: boolean) => {
      ctx.clearRect(0, 0, W, H);
      ctx.strokeStyle = "rgba(232,235,239,0.06)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (let x = 0; x <= W; x += GRID) {
        ctx.moveTo(x + 0.5, 0);
        ctx.lineTo(x + 0.5, H);
      }
      for (let y = 0; y <= H; y += GRID) {
        ctx.moveTo(0, y + 0.5);
        ctx.lineTo(W, y + 0.5);
      }
      ctx.stroke();
      for (const g of glows) {
        if (move) {
          g.x += (g.tx - g.x) * g.speed;
          g.y += (g.ty - g.y) * g.speed;
          if (Math.abs(g.tx - g.x) < 1 && Math.abs(g.ty - g.y) < 1) {
            g.tx = snap(W);
            g.ty = snap(H);
          }
          g.a = Math.min(1, g.a + 0.01);
        }
        const grad = ctx.createRadialGradient(g.x, g.y, 0, g.x, g.y, g.r);
        grad.addColorStop(0, PALETTE[g.ci] ?? PALETTE[0]!);
        grad.addColorStop(1, "rgba(10,13,18,0)");
        ctx.globalAlpha = g.a;
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(g.x, g.y, g.r, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 1;
      }
    };

    const resize = () => {
      const r = c.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      W = r.width;
      H = r.height;
      c.width = Math.round(W * dpr);
      c.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      glows = Array.from({ length: GLOWS }, make);
      draw(false);
    };

    const loop = () => {
      draw(true);
      frame = requestAnimationFrame(loop);
    };
    const run = () => {
      cancelAnimationFrame(frame);
      if (!still && visible && !document.hidden) frame = requestAnimationFrame(loop);
    };

    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(c);
    const io = new IntersectionObserver(([entry]) => {
      visible = entry?.isIntersecting ?? true;
      run();
    });
    io.observe(c);
    document.addEventListener("visibilitychange", run);
    run();

    return () => {
      cancelAnimationFrame(frame);
      ro.disconnect();
      io.disconnect();
      document.removeEventListener("visibilitychange", run);
    };
  }, []);

  return <canvas ref={ref} aria-hidden className="absolute inset-0 block size-full" style={{ opacity }} />;
}

const GLYPHS = "<>/\\[]{}=+*#01%&";

/** The word resolves out of noise once, letter by letter. */
export function useScramble(target: string): [word: string, replay: () => void] {
  const [word, setWord] = useState(target);
  // Bumping `run` plays the scramble again; a replay asked for mid-scramble is ignored.
  const [run, setRun] = useState(0);
  const running = useRef(false);
  useEffect(() => {
    if (reducedMotion()) return;
    running.current = true;
    let frame = 0;
    const timer = setInterval(() => {
      frame += 1;
      const done = frame > 8 + target.length * 5;
      setWord(
        done
          ? target
          : target
              .split("")
              .map((ch, i) => (frame > 8 + i * 5 ? ch : GLYPHS[Math.floor(Math.random() * GLYPHS.length)]))
              .join(""),
      );
      if (done) {
        clearInterval(timer);
        running.current = false;
      }
    }, 55);
    return () => {
      clearInterval(timer);
      running.current = false;
    };
  }, [target, run]);
  const replay = useCallback(() => {
    if (!running.current) setRun((r) => r + 1);
  }, []);
  return [word, replay];
}
