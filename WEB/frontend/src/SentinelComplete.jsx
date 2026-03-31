import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence, useMotionValue, useSpring, useTransform } from "framer-motion";
import DashboardPage from "./dashboard/DashboardPage.jsx";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

/* ═══════════════════════════════════════════════════════════════
   GLOBAL STYLES — merged both apps
═══════════════════════════════════════════════════════════════ */
const GlobalStyles = () => {
  useEffect(() => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700;900&family=JetBrains+Mono:wght@300;400;500&family=Syne:wght@400;600;700;800&display=swap";
    document.head.appendChild(link);
    const s = document.createElement("style");
    s.textContent = `
      *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
      html { scroll-behavior:smooth; }
      body { background:#020812; color:#C8DCEE; font-family:'Syne',sans-serif; overflow-x:hidden; cursor:none; }
      ::-webkit-scrollbar { width:3px; }
      ::-webkit-scrollbar-track { background:transparent; }
      ::-webkit-scrollbar-thumb { background:linear-gradient(to bottom,#00E5FF44,#7C3AED44); border-radius:99px; }
      #cursor-dot { position:fixed;width:8px;height:8px;border-radius:50%;background:#00E5FF;pointer-events:none;z-index:9999;transform:translate(-50%,-50%);box-shadow:0 0 12px #00E5FF,0 0 24px #00E5FF88;transition:width .15s,height .15s; }
      body:has(button:hover) #cursor-dot { width:12px;height:12px;background:#00FFA3; }
      .f-orb { font-family:'Orbitron',monospace; }
      .f-mono { font-family:'JetBrains Mono',monospace; }
      .f-syne { font-family:'Syne',sans-serif; }
      @keyframes aurora { 0%,100%{transform:translate(0,0) rotate(0deg) scale(1)} 25%{transform:translate(3%,2%) rotate(2deg) scale(1.03)} 50%{transform:translate(-2%,4%) rotate(-1deg) scale(0.97)} 75%{transform:translate(4%,-2%) rotate(3deg) scale(1.02)} }
      @keyframes aurora2 { 0%,100%{transform:translate(0,0) rotate(0deg) scale(1)} 33%{transform:translate(-4%,3%) rotate(-2deg) scale(1.04)} 66%{transform:translate(3%,-3%) rotate(2deg) scale(0.98)} }
      @keyframes spin { to{transform:rotate(360deg)} }
      @keyframes cspin { to{transform:rotate(-360deg)} }
      @keyframes float-y { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-18px)} }
      @keyframes float-y2 { 0%,100%{transform:translateY(-18px)} 50%{transform:translateY(0)} }
      @keyframes pulse-ring { 0%{transform:scale(.95);opacity:.9} 50%{transform:scale(1.05);opacity:.4} 100%{transform:scale(.95);opacity:.9} }
      @keyframes scan-v { 0%{top:-4px;opacity:0} 5%{opacity:.8} 95%{opacity:.8} 100%{top:100%;opacity:0} }
      @keyframes scan-h { 0%{transform:translateX(-100%)} 100%{transform:translateX(100vw)} }
      @keyframes blink { 50%{opacity:0} }
      @keyframes hue-shift { 0%{filter:hue-rotate(0deg)} 100%{filter:hue-rotate(360deg)} }
      @keyframes data-scroll { 0%{transform:translateX(0)} 100%{transform:translateX(-50%)} }
      @keyframes border-glow { 0%,100%{box-shadow:0 0 15px rgba(0,229,255,.2),inset 0 0 15px rgba(0,229,255,.03)} 50%{box-shadow:0 0 40px rgba(0,229,255,.35),inset 0 0 25px rgba(0,229,255,.07)} }
      @keyframes ticker { 0%{transform:translateX(0)} 100%{transform:translateX(-50%)} }
      @keyframes shimmer { 0%{background-position:200% center} 100%{background-position:-200% center} }
      @keyframes pulse-glow { 0%,100%{opacity:.4;transform:scale(1)} 50%{opacity:.8;transform:scale(1.06)} }
      .anim-aurora1 { animation:aurora 18s ease-in-out infinite; }
      .anim-aurora2 { animation:aurora2 22s ease-in-out infinite; }
      .anim-float { animation:float-y 5s ease-in-out infinite; }
      .anim-float2 { animation:float-y2 5s ease-in-out infinite; }
      
      .glass-card { background:linear-gradient(135deg,rgba(8,20,40,.85) 0%,rgba(4,10,22,.9) 100%);border:1px solid rgba(0,229,255,.1);border-radius:16px;position:relative;overflow:hidden; }
      .glass-card::before { content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(0,229,255,.04) 0%,transparent 50%,rgba(124,58,237,.03) 100%);pointer-events:none; }
      .glass-card-glow { border-color:rgba(0,229,255,.28) !important;box-shadow:0 0 50px rgba(0,229,255,.1),0 0 100px rgba(0,229,255,.04) !important; }
      .grad-border { position:relative;border-radius:16px; }
      .grad-border::after { content:'';position:absolute;inset:-1px;border-radius:17px;background:linear-gradient(135deg,rgba(0,229,255,.5),rgba(124,58,237,.3),rgba(0,255,163,.4));z-index:-1;opacity:0;transition:opacity .3s; }
      .grad-border:hover::after { opacity:1; }
      .cyber-input { width:100%;background:rgba(0,0,0,.5);border:1px solid rgba(0,229,255,.12);border-radius:10px;color:#C8DCEE;font-family:'JetBrains Mono',monospace;font-size:14px;outline:none;transition:border-color .25s,box-shadow .25s,background .25s; }
      .cyber-input:focus { border-color:rgba(0,229,255,.45);background:rgba(0,229,255,.03);box-shadow:0 0 0 3px rgba(0,229,255,.05),0 0 25px rgba(0,229,255,.08); }
      .cyber-input::placeholder { color:rgba(100,140,170,.4); }
      .threat-tag { display:inline-flex;align-items:center;gap:7px;padding:6px 14px;border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:12px;letter-spacing:.9px;cursor:default;transition:transform .2s,box-shadow .2s;position:relative;overflow:hidden; }
      .threat-tag:hover { transform:translateY(-2px) scale(1.04); }
      .ticker-content { display:inline-block; animation:data-scroll 22s linear infinite; }
      .shimmer-text { background:linear-gradient(90deg,#00FF41,#00E5FF,#00FFA3,#00FF41);background-size:300% auto;-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:shimmer 4s linear infinite; }
      .glass-lp { background:rgba(0,255,65,.03);border:1px solid rgba(0,255,65,.12); }
      .fade-in { animation:fadeUp .6s ease both; }
      @keyframes fadeUp { from{opacity:0;transform:translateY(24px)} to{opacity:1;transform:translateY(0)} }
      nav a { text-decoration:none; }
    `;
    document.head.appendChild(s);
    const dot = document.createElement("div"); dot.id="cursor-dot";
    document.body.appendChild(dot);
    const moveCursor = e => { dot.style.left=e.clientX+"px"; dot.style.top=e.clientY+"px"; };
    window.addEventListener("mousemove",moveCursor);
    return () => { try{document.head.removeChild(link);document.head.removeChild(s);}catch(e){} try{document.body.removeChild(dot);}catch(e){} window.removeEventListener("mousemove",moveCursor); };
  }, []);
  return null;
};


const AuroraBlobs = () => (
  <div style={{position:"fixed",inset:0,zIndex:0,pointerEvents:"none",overflow:"hidden"}}>
    <div className="anim-aurora1" style={{position:"absolute",width:"80vw",height:"80vh",top:"-20vh",left:"-10vw",background:"radial-gradient(ellipse at center,rgba(0,229,255,.04) 0%,transparent 65%)"}}/>
    <div className="anim-aurora2" style={{position:"absolute",width:"70vw",height:"70vh",bottom:"-20vh",right:"-10vw",background:"radial-gradient(ellipse at center,rgba(124,58,237,.04) 0%,transparent 65%)"}}/>
  </div>
);

/* ═══════════════════════════════════════════════════════════════
   THREAT RADAR — smooth sweep-arm + delta-time + offscreen canvas
═══════════════════════════════════════════════════════════════ */
const ThreatRadar = ({ mx, my }) => {
  const canvasRef = useRef(null);
  const rafRef    = useRef(null);
  const ppx = useTransform(mx, [0,typeof window!=="undefined"?window.innerWidth:1200],[-8,8]);
  const ppy = useTransform(my, [0,typeof window!=="undefined"?window.innerHeight:800],[-5,5]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if(!canvas) return;
    const ctx = canvas.getContext("2d");
    const S = 580, DPR = Math.min(window.devicePixelRatio||1, 2);
    canvas.width = S*DPR; canvas.height = S*DPR;
    canvas.style.width = S+"px"; canvas.style.height = S+"px";
    ctx.scale(DPR, DPR);

    const CX=S/2, CY=S/2, PAD=32, R=S/2-PAD-10;
    const TAU = Math.PI*2;
    const GD  = a => `rgba(0,255,65,${a})`;
    const RD  = a => `rgba(255,80,80,${a})`;
    const CD  = a => `rgba(0,229,255,${a})`;
    const RPM = 1/7; // one rotation per 7s — slow, cinematic
    const WORLD_SPEED = 16; // px per second downward drift
    let worldY = 0;

    // Threats use cartesian world coords (wx, wy); worldY scrolls them downward
    const THREATS = [
      { label:"PHISH-URL",  locked:true,  wx:-120, wy:-80  },
      { label:"SPOOF-DOM",  locked:true,  wx: 130, wy:-200 },
      { label:"MAL-ATTACH", locked:true,  wx:-60,  wy: 120 },
      { label:"TRACK-PXL",  locked:false, wx: 175, wy: 55  },
      { label:"HTML-INJ",   locked:false, wx:-185, wy: 250 },
      { label:"OBFUS-URL",  locked:true,  wx: 55,  wy:-260 },
      { label:"BEC-SIGNAL", locked:false, wx: 195, wy:-140 },
      { label:"URGENCY",    locked:false, wx:-25,  wy: 320 },
      { label:"C2-BEACON",  locked:true,  wx: 75,  wy: 230 },
      { label:"EXFIL",      locked:false, wx:-145, wy:-340 },
      { label:"RANSOM-C2",  locked:true,  wx: 90,  wy: 400 },
      { label:"DNS-SPOOF",  locked:true,  wx:-200, wy:-160 },
      { label:"MACRO-INJ",  locked:false, wx: 160, wy:-320 },
      { label:"CRED-HARV",  locked:true,  wx:-100, wy: 180 },
    ].map(t => ({ ...t, echo:0, pulseR:0 }));

    // ── Pre-render static layer (inner radar + decorative bezel) ─────
    const bg = document.createElement("canvas");
    bg.width = S*DPR; bg.height = S*DPR;
    const bx = bg.getContext("2d");
    bx.scale(DPR, DPR);

    // ① Inner circle background + grid + rings
    bx.save();
    bx.beginPath(); bx.arc(CX,CY,R,0,TAU); bx.clip();
    bx.fillStyle="rgba(0,12,3,1)"; bx.fillRect(0,0,S,S);
    // radial gradient overlay for depth
    const rg = bx.createRadialGradient(CX,CY,0,CX,CY,R);
    rg.addColorStop(0,"rgba(0,40,8,0.6)"); rg.addColorStop(0.6,"rgba(0,18,4,0.2)"); rg.addColorStop(1,"rgba(0,0,0,0.5)");
    bx.fillStyle=rg; bx.fillRect(0,0,S,S);
    // faint grid
    bx.strokeStyle="rgba(0,180,50,0.04)"; bx.lineWidth=0.5;
    const GS=34;
    for(let x=0;x<S;x+=GS){bx.beginPath();bx.moveTo(x,0);bx.lineTo(x,S);bx.stroke();}
    for(let y=0;y<S;y+=GS){bx.beginPath();bx.moveTo(0,y);bx.lineTo(S,y);bx.stroke();}
    // 4 range rings
    for(let i=1;i<=4;i++){
      const rr=(R/4)*i;
      bx.beginPath(); bx.arc(CX,CY,rr,0,TAU);
      if(i===4){ bx.strokeStyle=GD(0.32); bx.lineWidth=1.0; }
      else      { bx.strokeStyle=GD(0.07); bx.lineWidth=0.5; }
      bx.stroke();
      // range label
      if(i<4){ bx.font="7px 'JetBrains Mono',monospace"; bx.fillStyle=GD(0.2); bx.textAlign="left"; bx.fillText(`${i*25}%`,CX+rr+3,CY-2); }
    }
    // crosshair axes
    bx.strokeStyle=GD(0.1); bx.lineWidth=0.5;
    [[CX-R,CY,CX+R,CY],[CX,CY-R,CX,CY+R]].forEach(([x1,y1,x2,y2])=>{bx.beginPath();bx.moveTo(x1,y1);bx.lineTo(x2,y2);bx.stroke();});
    // 45° diagonal marks
    bx.strokeStyle=GD(0.05); bx.lineWidth=0.4;
    [Math.PI/4,3*Math.PI/4].forEach(a=>{
      bx.beginPath(); bx.moveTo(CX-Math.cos(a)*R,CY-Math.sin(a)*R); bx.lineTo(CX+Math.cos(a)*R,CY+Math.sin(a)*R); bx.stroke();
    });
    bx.restore();

    // ② Outer bezel rings (3 concentric)
    bx.beginPath(); bx.arc(CX,CY,R+2,0,TAU);  bx.strokeStyle=GD(0.5);  bx.lineWidth=2;   bx.stroke();
    bx.beginPath(); bx.arc(CX,CY,R+9,0,TAU);  bx.strokeStyle=GD(0.18); bx.lineWidth=6;   bx.stroke();
    bx.beginPath(); bx.arc(CX,CY,R+12,0,TAU); bx.strokeStyle=GD(0.55); bx.lineWidth=1.2; bx.stroke();
    bx.beginPath(); bx.arc(CX,CY,R+22,0,TAU); bx.strokeStyle=GD(0.08); bx.lineWidth=0.5; bx.stroke();

    // ③ 36 ticks on bezel
    for(let i=0;i<36;i++){
      const a=(i/36)*TAU, maj=i%9===0, med=i%3===0;
      const r1=R+12, r2=R+(maj?22:med?18:15);
      bx.beginPath(); bx.moveTo(CX+Math.cos(a)*r1,CY+Math.sin(a)*r1); bx.lineTo(CX+Math.cos(a)*r2,CY+Math.sin(a)*r2);
      bx.strokeStyle=GD(maj?.75:med?.35:.15); bx.lineWidth=maj?1.4:med?.7:.4; bx.stroke();
      if(maj){
        const deg = i*10;
        bx.font="bold 8px 'JetBrains Mono',monospace"; bx.textAlign="center";
        bx.fillStyle=GD(0.45);
        bx.fillText(String(deg).padStart(3,"0"), CX+Math.cos(a)*(R+28), CY+Math.sin(a)*(R+28)+3);
      }
    }

    // ④ Arc text — top: "◆ SENTINEL THREAT RADAR ◆", bottom: "◇ EMAIL ANALYZER v2.0 ◇"
    const drawArcText = (text, arcR, startA, dir, style, size) => {
      bx.font=`${style} ${size}px 'JetBrains Mono',monospace`;
      bx.textAlign="center"; bx.textBaseline="middle";
      const total = text.length;
      const step = (dir==="top" ? -1 : 1) * 0.072;
      const offset = step * (total-1) / 2;
      for(let i=0;i<total;i++){
        const charA = startA + (i - (total-1)/2) * step * (dir==="top"?-1:1);
        bx.save();
        bx.translate(CX+Math.cos(charA)*arcR, CY+Math.sin(charA)*arcR);
        bx.rotate(charA + (dir==="top"?-Math.PI/2:Math.PI/2));
        bx.fillText(text[i],0,0);
        bx.restore();
      }
      bx.textBaseline="alphabetic";
    };
    bx.fillStyle=GD(0.4);
    drawArcText("◆  ACTIVE THREAT DETECTION SYSTEM  ◆", R+36, -Math.PI/2, "top", "bold", 7);
    bx.fillStyle=GD(0.25);
    drawArcText("◇  SENTINEL  AI  RADAR  v2.0  ◇", R+36, Math.PI/2, "bottom", "", 7);

    // ⑤ Side data panels (static decorative)
    const panH=110, panW=42, panY=CY-panH/2;
    const LP = PAD*.3;
    // Left panel bg
    bx.fillStyle="rgba(0,255,65,0.025)"; bx.fillRect(LP,panY,panW,panH);
    bx.strokeStyle=GD(0.18); bx.lineWidth=0.7; bx.strokeRect(LP,panY,panW,panH);
    // Left panel: signal strength bars
    bx.font="7px 'JetBrains Mono',monospace"; bx.textAlign="left"; bx.fillStyle=GD(0.4);
    bx.fillText("SIG",LP+4,panY+11);
    for(let b=0;b<5;b++){
      const bh=5+b*5, active=b<4;
      bx.fillStyle=active?GD(0.65):GD(0.1);
      bx.fillRect(LP+4+b*7,panY+24,4,bh);
    }
    bx.fillStyle=GD(0.4); bx.fillText("LAT",LP+4,panY+58);
    bx.fillStyle=GD(0.7); bx.fillText("10.8234",LP+4,panY+68);
    bx.fillStyle=GD(0.4); bx.fillText("LON",LP+4,panY+80);
    bx.fillStyle=GD(0.7); bx.fillText("106.629",LP+4,panY+90);
    bx.fillStyle=GD(0.4); bx.fillText("ALT",LP+4,panY+102);
    bx.fillStyle=GD(0.7); bx.fillText("0142m",LP+4,panY+112);
    // Right panel
    const RP = S - LP - panW;
    bx.fillStyle="rgba(0,255,65,0.025)"; bx.fillRect(RP,panY,panW,panH);
    bx.strokeStyle=GD(0.18); bx.lineWidth=0.7; bx.strokeRect(RP,panY,panW,panH);
    bx.font="7px 'JetBrains Mono',monospace"; bx.textAlign="left"; bx.fillStyle=GD(0.4);
    bx.fillText("THRT",RP+3,panY+11);
    bx.font="bold 15px 'JetBrains Mono',monospace"; bx.fillStyle=RD(0.85);
    bx.fillText("05",RP+5,panY+28);
    bx.font="7px 'JetBrains Mono',monospace"; bx.fillStyle=GD(0.35); bx.fillText("LOCK",RP+3,panY+38);
    bx.fillStyle=GD(0.4); bx.fillText("FREQ",RP+3,panY+54);
    bx.fillStyle=GD(0.75); bx.fillText("0.55G",RP+3,panY+64);
    bx.fillStyle=GD(0.4); bx.fillText("MODE",RP+3,panY+78);
    bx.fillStyle=GD(0.75); bx.fillText("SCAN",RP+3,panY+88);
    bx.fillStyle=GD(0.4); bx.fillText("SENS",RP+3,panY+102);
    bx.fillStyle=GD(0.75); bx.fillText("AUTO",RP+3,panY+112);

    // ⑥ Outer frame + corner brackets
    bx.strokeStyle="rgba(0,180,50,0.3)"; bx.lineWidth=1.2; bx.strokeRect(1,1,S-2,S-2);
    bx.strokeStyle="rgba(0,180,50,0.07)"; bx.lineWidth=0.5; bx.strokeRect(PAD*.4,PAD*.4,S-PAD*.8,S-PAD*.8);
    bx.strokeStyle=GD(0.55); bx.lineWidth=1.8;
    [[8,8,1,1],[S-8,8,-1,1],[S-8,S-8,-1,-1],[8,S-8,1,-1]].forEach(([px,py,sx,sy])=>{
      bx.beginPath(); bx.moveTo(px,py+sy*18); bx.lineTo(px,py); bx.lineTo(px+sx*18,py); bx.stroke();
      bx.beginPath(); bx.arc(px,py,2,0,TAU); bx.fillStyle=GD(0.8); bx.fill();
    });
    // ⑦ Top-left and top-right HUD labels (static)
    bx.font="bold 8px 'JetBrains Mono',monospace"; bx.fillStyle=GD(0.5); bx.textAlign="left";
    bx.fillText("SENTINEL:", 14, 20);
    bx.font="7px 'JetBrains Mono',monospace"; bx.fillStyle=CD(0.4); bx.textAlign="right";
    bx.fillText("SYSTEM ACTIVE", S-14, 20);

    // ── Animation state ────────────────────────────────────────
    let sweepAngle = -Math.PI/2;
    let lastTime = null;
    let blinkT = 0;
    let scanProgressT = 0;

    const draw = (ts) => {
      if(!lastTime) lastTime = ts;
      const dt = Math.min((ts - lastTime)/1000, 0.05);
      lastTime = ts;
      sweepAngle = (sweepAngle + dt*TAU*RPM) % TAU;
      blinkT += dt;
      scanProgressT = (scanProgressT + dt*0.9) % 1;

      // Scroll world downward
      worldY += WORLD_SPEED * dt;
      // Wrap threats: when a threat scrolls too far below centre, re-enter from top
      THREATS.forEach(t => {
        // screen position from world coords
        t.sx = CX + t.wx;
        t.sy = CY + (t.wy + worldY);
        // Wrap: when threat drifts below radar, re-enter from top
        if(t.sy > CY + R*1.4) {
          t.wy -= R*2.8;
          t.sy = CY + (t.wy + worldY);
        }
      });

      // Detect threat hits by current screen position angle from centre
      THREATS.forEach(t => {
        t.echo = Math.max(0, t.echo - dt*0.22);
        // Compute current polar angle of this threat from centre
        const dx = t.sx - CX, dy = t.sy - CY;
        const dist = Math.hypot(dx, dy);
        if(dist > R || dist < 4) return; // outside radar or at centre
        const ta = (Math.atan2(dy, dx) % TAU + TAU) % TAU;
        let sw   = ((sweepAngle % TAU) + TAU) % TAU;
        let prev = ((sweepAngle - dt*TAU*RPM) % TAU + TAU) % TAU;
        const crossed = prev < sw ? ta >= prev && ta <= sw : ta >= prev || ta <= sw;
        if(crossed){ t.echo=1.0; t.pulseR=0; }
        if(t.echo>0) t.pulseR = Math.min(t.pulseR + dt*60, 50);
      });

      // ── Draw ──────────────────────────────────────────────
      ctx.clearRect(0,0,S,S);
      ctx.drawImage(bg, 0,0, S*DPR,S*DPR, 0,0, S,S);

      // ── Inside circle clip ──────────────────────────────
      ctx.save();
      ctx.beginPath(); ctx.arc(CX,CY,R,0,TAU); ctx.clip();

      // Sweep glow fan (28 slices, quadratic fade)
      const FAN = Math.PI*0.7;
      for(let i=0;i<28;i++){
        const frac=(i+1)/28, frac2=frac*frac;
        const a0=sweepAngle-FAN*(1-frac), a1=sweepAngle-FAN*(1-(i+2)/28);
        ctx.beginPath(); ctx.moveTo(CX,CY); ctx.arc(CX,CY,R,a0,a1); ctx.closePath();
        ctx.fillStyle=`rgba(0,255,65,${frac2*0.07})`;
        ctx.fill();
      }
      // Sweep arm — bright edge with a soft halo line
      ctx.beginPath(); ctx.moveTo(CX,CY);
      ctx.lineTo(CX+Math.cos(sweepAngle)*R, CY+Math.sin(sweepAngle)*R);
      ctx.strokeStyle="rgba(80,255,120,0.95)"; ctx.lineWidth=2; ctx.stroke();
      ctx.beginPath(); ctx.moveTo(CX,CY);
      ctx.lineTo(CX+Math.cos(sweepAngle)*R, CY+Math.sin(sweepAngle)*R);
      ctx.strokeStyle="rgba(0,255,65,0.2)"; ctx.lineWidth=7; ctx.stroke();

      // Threat blips
      THREATS.forEach(t => {
        if(t.echo<=0.01 || !t.sx) return;
        const a=t.echo, col=t.locked?"255,80,80":"0,255,65";
        // Expanding pulse ring
        if(t.pulseR>0 && t.pulseR<48){
          ctx.beginPath(); ctx.arc(t.sx,t.sy,t.pulseR,0,TAU);
          ctx.strokeStyle=`rgba(${col},${a*(1-t.pulseR/50)*0.6})`; ctx.lineWidth=1; ctx.stroke();
        }
        // Two echo rings
        [12,22].forEach((rr,ri)=>{
          ctx.beginPath(); ctx.arc(t.sx,t.sy,rr,0,TAU);
          ctx.strokeStyle=`rgba(${col},${a*(0.55-ri*.2)})`; ctx.lineWidth=1.2-ri*.3; ctx.stroke();
        });
        // Core dot / icon
        ctx.save(); ctx.globalAlpha=Math.min(1,a*1.1); ctx.translate(t.sx,t.sy);
        if(t.locked){
          ctx.beginPath(); ctx.moveTo(0,-8); ctx.lineTo(-5.5,5); ctx.lineTo(5.5,5); ctx.closePath();
          ctx.fillStyle="rgba(255,80,80,1)"; ctx.fill();
          const SZ=13,ARM=4;
          ctx.strokeStyle="rgba(255,80,80,0.75)"; ctx.lineWidth=1.2;
          [[-1,-1],[1,-1],[1,1],[-1,1]].forEach(([sx,sy])=>{
            ctx.beginPath(); ctx.moveTo(sx*SZ,sy*(SZ-ARM)); ctx.lineTo(sx*SZ,sy*SZ); ctx.lineTo(sx*(SZ-ARM),sy*SZ); ctx.stroke();
          });
        } else {
          // Diamond dot
          ctx.beginPath(); ctx.moveTo(0,-5); ctx.lineTo(4,0); ctx.lineTo(0,5); ctx.lineTo(-4,0); ctx.closePath();
          ctx.fillStyle="rgba(0,255,65,1)"; ctx.fill();
        }
        ctx.restore();
        // Label with leader line
        if(a>0.1){
          const right=t.sx>CX, lx=t.sx+(right?22:-22), ly=t.sy-5;
          ctx.globalAlpha=a*0.95;
          ctx.beginPath(); ctx.moveTo(t.sx+(right?10:-10),t.sy); ctx.lineTo(lx+(right?-3:3),ly+4);
          ctx.strokeStyle=t.locked?`rgba(255,100,100,${a*0.5})`:`rgba(0,255,65,${a*0.4})`; ctx.lineWidth=0.7; ctx.stroke();
          ctx.fillStyle=t.locked?"rgba(255,110,110,1)":"rgba(0,255,65,1)";
          ctx.font="bold 8px 'JetBrains Mono',monospace";
          ctx.textAlign=right?"left":"right";
          ctx.fillText(t.label, lx, ly);
          ctx.globalAlpha=1; ctx.textAlign="left";
        }
      });

      // Centre emitter crosshair
      ctx.strokeStyle="rgba(160,255,180,0.6)"; ctx.lineWidth=0.7;
      [[CX-10,CY,CX-3,CY],[CX+3,CY,CX+10,CY],[CX,CY-10,CX,CY-3],[CX,CY+3,CX,CY+10]].forEach(([x1,y1,x2,y2])=>{
        ctx.beginPath(); ctx.moveTo(x1,y1); ctx.lineTo(x2,y2); ctx.stroke();
      });
      ctx.beginPath(); ctx.arc(CX,CY,3,0,TAU); ctx.fillStyle="rgba(200,255,200,0.95)"; ctx.fill();

      ctx.restore(); // end clip

      // ── Outside clip: dynamic HUD ──────────────────────────
      const found = THREATS.filter(t=>t.echo>0.05);
      const locked = found.filter(t=>t.locked);

      // Threat list top-left (dynamic, next to "SENTINEL:")
      ctx.font="bold 7px 'JetBrains Mono',monospace"; ctx.textAlign="left";
      let hx=78;
      found.slice(0,6).forEach(t=>{
        ctx.fillStyle=t.locked?"rgba(255,90,90,0.9)":"rgba(0,255,65,0.75)";
        ctx.fillText(t.label, hx, 20);
        hx += ctx.measureText(t.label).width + 8;
      });

      // LIVE blink + counter (top-right)
      ctx.font="7px 'JetBrains Mono',monospace"; ctx.textAlign="right"; ctx.fillStyle=GD(0.35); ctx.globalAlpha=0.8;
      ctx.fillText(`${found.length}/${THREATS.length} DETECTED`, S-28, 20);
      ctx.globalAlpha=1;
      if(Math.sin(blinkT*Math.PI*2)>0){
        ctx.beginPath(); ctx.arc(S-18,14,3.5,0,TAU); ctx.fillStyle="rgba(255,70,70,0.9)"; ctx.fill();
      }
      ctx.fillStyle="rgba(255,70,70,0.5)"; ctx.font="6px 'JetBrains Mono',monospace"; ctx.textAlign="right";
      ctx.fillText("LIVE", S-24, 14);

      // Scan progress bar (bottom)
      const barY=S-11, barX=PAD+4, barW=S-PAD*2-8;
      ctx.strokeStyle=GD(0.15); ctx.lineWidth=0.5; ctx.strokeRect(barX,barY,barW,4);
      const norm = ((sweepAngle+Math.PI/2)%TAU+TAU)%TAU / TAU;
      ctx.fillStyle=GD(0.45); ctx.fillRect(barX,barY,barW*norm,4);
      ctx.font="6px 'JetBrains Mono',monospace"; ctx.textAlign="left"; ctx.fillStyle=GD(0.3);
      ctx.fillText("SCAN PROGRESS", barX, barY-2);
      ctx.textAlign="right";
      ctx.fillText(`LOCKED: ${locked.length}`, S-barX, barY-2);

      rafRef.current = requestAnimationFrame(draw);
    };

    rafRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(rafRef.current);
  }, []);

  return (
    <motion.div style={{x:ppx, y:ppy}}>
      <div style={{position:"relative",width:580,height:580,margin:"0 auto"}}>
        <div style={{position:"absolute",inset:-48,borderRadius:"50%",
          background:"radial-gradient(circle,rgba(0,255,65,0.07) 0%,transparent 60%)",
          animation:"pulse-glow 4s ease-in-out infinite",pointerEvents:"none"}}/>
        <canvas ref={canvasRef} style={{display:"block"}}/>
      </div>
    </motion.div>
  );
};



/* ═══════════════════════════════════════════════════════════════
   SHARED SMALL COMPONENTS
═══════════════════════════════════════════════════════════════ */
const ScanLine = () => (
  <div style={{position:"fixed",left:0,right:0,height:2,zIndex:200,pointerEvents:"none",background:"linear-gradient(90deg,transparent 0%,rgba(0,229,255,.08) 15%,rgba(0,229,255,.9) 50%,rgba(0,229,255,.08) 85%,transparent 100%)",boxShadow:"0 0 20px rgba(0,229,255,.6),0 0 60px rgba(0,229,255,.3)",animation:"scan-v 2.6s linear infinite"}} />
);
const TypeWriter = ({texts}) => {
  const [i,setI]=useState(0),[disp,setDisp]=useState(""),[ci,setCi]=useState(0);
  useEffect(()=>{const cur=texts[i%texts.length];if(ci<cur.length){const t=setTimeout(()=>{setDisp(cur.slice(0,ci+1));setCi(c=>c+1);},36);return()=>clearTimeout(t);}const t=setTimeout(()=>{setI(x=>x+1);setCi(0);setDisp("");},1100);return()=>clearTimeout(t);},[ci,i]);
  return <span className="f-mono" style={{color:"#00E5FF",fontSize:12,letterSpacing:.8}}>{disp}<span style={{animation:"blink 1s step-end infinite",color:"#00FFA3"}}>▌</span></span>;
};
const AnimNum = ({to,suffix=""}) => <span>{to}{suffix}</span>;
const RiskGauge = ({score}) => {
  const R=58,C=2*Math.PI*R,pct=score/100,stopA=pct<.3?"#00FFA3":pct<.6?"#FFD60A":"#FF4D6D",stopB=pct<.3?"#00E5FF":pct<.6?"#FF9500":"#FF0055",label=pct<.3?"LOW RISK":pct<.6?"MODERATE":"HIGH RISK",glowColor=pct<.3?"rgba(0,255,163,.4)":pct<.6?"rgba(255,214,10,.4)":"rgba(255,77,109,.4)";
  return (<div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:12}}><div style={{position:"relative",width:156,height:156}}><svg width="156" height="156" style={{transform:"rotate(-90deg)",position:"absolute"}}><defs><linearGradient id="arc-grad" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor={stopA}/><stop offset="100%" stopColor={stopB}/></linearGradient></defs><circle cx="78" cy="78" r={R} fill="none" stroke="rgba(255,255,255,.05)" strokeWidth="10"/><circle cx="78" cy="78" r={R} fill="none" stroke="url(#arc-grad)" strokeWidth="10" strokeLinecap="round" strokeDasharray={C} strokeDashoffset={C-(pct*C)}/></svg><div style={{position:"absolute",inset:0,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center"}}><div className="f-orb" style={{fontSize:36,fontWeight:900,color:stopA,lineHeight:1}}>{score}</div><div className="f-mono" style={{fontSize:11,color:stopA,letterSpacing:2.2,marginTop:5,opacity:.8}}>/100</div></div></div><div className="f-mono" style={{fontSize:11,letterSpacing:3.2,color:stopA,background:`${stopA}12`,border:`1px solid ${stopA}30`,padding:"5px 14px",borderRadius:5}}>{label}</div></div>);
};
const StatCard = ({icon,label,value,color,raw}) => (<div style={{background:`linear-gradient(135deg,${color}08,rgba(0,0,0,.4))`,border:`1px solid ${color}20`,borderRadius:12,padding:"20px 16px",textAlign:"center",position:"relative",overflow:"hidden"}}><div style={{fontSize:24,marginBottom:10}}>{icon}</div><div className="f-orb" style={{fontSize:28,color,fontWeight:900,lineHeight:1}}>{raw?value:value}</div><div className="f-mono" style={{fontSize:11,color:"rgba(100,140,170,.72)",letterSpacing:1.8,marginTop:8}}>{label}</div></div>);
const Panel = ({title,icon,color="#00E5FF",children,delay=0,defaultOpen=false}) => {
  const [open,setOpen]=useState(defaultOpen);
  return (<div className="glass-card" style={{marginBottom:12,overflow:"hidden",border:`1px solid ${color}15`}}><button onClick={()=>setOpen(o=>!o)} style={{width:"100%",padding:"18px 22px",display:"flex",alignItems:"center",justifyContent:"space-between",background:"none",border:"none",cursor:"pointer"}}><div style={{display:"flex",alignItems:"center",gap:14}}><div style={{width:36,height:36,borderRadius:10,background:`${color}12`,border:`1px solid ${color}28`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:18}}>{icon}</div><span className="f-orb" style={{color:"#A8C0D8",fontSize:13,letterSpacing:2.8}}>{title}</span></div><span style={{color,fontSize:14,transition:"transform .2s",display:"inline-block",transform:open?"rotate(180deg)":"none"}}>▾</span></button>{open&&<div style={{padding:"6px 22px 22px",borderTop:`1px solid ${color}12`}}>{children}</div>}</div>);
};
const Tag = ({label,color}) => (<span className="threat-tag" style={{color,background:`${color}0D`,border:`1px solid ${color}38`}}><span style={{width:5,height:5,borderRadius:"50%",background:color,display:"inline-block",flexShrink:0}}/>{label}</span>);
const Verdict = ({v,labelOverride,subOverride}) => {
  const map = {
    HAM: { c: "#00FFA3", label: "SAFE", sub: "Low combined risk" },
    SUSPICIOUS: { c: "#FFD60A", label: "SUSPICIOUS", sub: "Manual review advised" },
    SPAM: { c: "#FF9500", label: "SPAM", sub: "High combined spam risk" },
    THREAT: { c: "#FF4D6D", label: "THREAT", sub: "High confidence malicious signals" },
  };
  const { c, label, sub } = map[v] || map.SUSPICIOUS;
  const finalLabel = labelOverride || label;
  const finalSub = subOverride || sub;
  return (
    <motion.div initial={{scale:.5,opacity:0}} animate={{scale:1,opacity:1}} transition={{type:"spring",stiffness:160,damping:12}} style={{padding:"20px 28px",borderRadius:14,background:`linear-gradient(135deg,${c}08 0%,rgba(0,0,0,.5) 100%)`,border:`1px solid ${c}40`,textAlign:"center",boxShadow:`0 0 40px ${c}18,0 0 80px ${c}08`}}>
      <div className="f-mono" style={{fontSize:11,color:`${c}88`,letterSpacing:4.2,marginBottom:10}}>VERDICT</div>
      <div className="f-orb" style={{fontSize:32,fontWeight:900,color:c,letterSpacing:2.2,textShadow:`0 0 30px ${c}99`}}>{finalLabel}</div>
      <div className="f-mono" style={{fontSize:12,color:`${c}66`,marginTop:8,letterSpacing:.6}}>{finalSub}</div>
    </motion.div>
  );
};
const BarStat = ({label,val,color}) => (<div style={{marginBottom:6}}><div style={{display:"flex",justifyContent:"space-between",marginBottom:9}}><span className="f-mono" style={{fontSize:11,color:"rgba(100,140,170,.72)",letterSpacing:1.8}}>{label}</span><span className="f-mono" style={{fontSize:14,color,fontWeight:500}}>{val}%</span></div><div style={{height:6,background:"rgba(255,255,255,.04)",borderRadius:99,overflow:"hidden"}}><div style={{width:`${val}%`,height:"100%",background:`linear-gradient(90deg,${color}60,${color})`,borderRadius:99}}/></div></div>);
const ScanAnim = () => (<motion.div initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}} style={{display:"flex",flexDirection:"column",alignItems:"center",gap:20,padding:"32px 0"}}><div style={{position:"relative",width:88,height:88}}><div style={{position:"absolute",inset:0,borderRadius:"50%",border:"2px solid rgba(0,229,255,.15)",borderTopColor:"#00E5FF",animation:"spin 1s linear infinite"}}/><div style={{position:"absolute",inset:10,borderRadius:"50%",border:"1.5px solid rgba(0,255,163,.12)",borderBottomColor:"#00FFA3",animation:"cspin 1.6s linear infinite"}}/><div style={{position:"absolute",inset:20,borderRadius:"50%",border:"1px solid rgba(124,58,237,.15)",borderLeftColor:"#7C3AED",animation:"spin 2.2s linear infinite"}}/><div style={{position:"absolute",inset:0,display:"flex",alignItems:"center",justifyContent:"center"}}><div style={{width:14,height:14,borderRadius:"50%",background:"#00E5FF",boxShadow:"0 0 20px #00E5FF,0 0 40px #00E5FF66",animation:"pulse-ring 1.2s ease-in-out infinite"}}/></div></div><TypeWriter texts={["Parsing MIME structure...","Resolving sender domain...","Extracting anchor tags...","Analyzing language entropy...","Checking URL reputation...","Computing threat vectors...","Generating AI verdict..."]}/></motion.div>);

const ModelModeCard = ({meta, active, onClick}) => (
  <motion.button
    onClick={onClick}
    whileHover={{ y: -4, scale: 1.01 }}
    whileTap={{ scale: 0.99 }}
    style={{
      textAlign: "left",
      borderRadius: 18,
      padding: "20px 20px 18px",
      border: `1px solid ${active ? meta.accent : "rgba(110,140,170,.14)"}`,
      background: active
        ? `linear-gradient(160deg, ${meta.accentSoft} 0%, rgba(5,14,28,.96) 65%)`
        : "linear-gradient(160deg, rgba(7,16,30,.92) 0%, rgba(3,9,20,.98) 100%)",
      boxShadow: active
        ? `0 0 40px ${meta.glow}, inset 0 1px 0 rgba(255,255,255,.06)`
        : "inset 0 1px 0 rgba(255,255,255,.03)",
      cursor: "pointer",
      transition: "all .25s ease",
      overflow: "hidden",
      position: "relative",
    }}
  >
    <div style={{position:"absolute",top:0,left:0,right:0,height:2,background:`linear-gradient(90deg, transparent, ${meta.accent}, transparent)`,opacity:active?.9:.3}} />
    <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:14}}>
      <div style={{display:"flex",alignItems:"center",gap:12}}>
        <div style={{width:42,height:42,borderRadius:12,display:"flex",alignItems:"center",justifyContent:"center",fontSize:20,background:`${meta.accent}15`,border:`1px solid ${meta.accent}33`}}>{meta.icon}</div>
        <div>
          <div className="f-orb" style={{fontSize:14,letterSpacing:2.3,color:active?meta.accent:"#D0E8F8"}}>{meta.title}</div>
          <div className="f-mono" style={{fontSize:11,color:"rgba(120,150,175,.6)",letterSpacing:1.4,marginTop:5}}>{meta.source}</div>
        </div>
      </div>
      <div className="f-mono" style={{fontSize:10,color:active?meta.accent:"rgba(120,150,175,.45)",letterSpacing:1.7}}>
        {active ? "ACTIVE" : "SELECT"}
      </div>
    </div>
    <div className="f-syne" style={{fontSize:15,color:"rgba(190,214,235,.78)",lineHeight:1.72,minHeight:78}}>
      {meta.description}
    </div>
    <div style={{display:"flex",flexWrap:"wrap",gap:8,marginTop:14,marginBottom:12}}>
      {meta.chips.map((chip)=>(
        <span key={chip} className="f-mono" style={{fontSize:10,color:active?meta.accent:"rgba(120,150,175,.6)",letterSpacing:1.3,padding:"5px 11px",borderRadius:999,background:active?`${meta.accent}10`:"rgba(110,140,170,.06)",border:`1px solid ${active?`${meta.accent}2E`:"rgba(110,140,170,.12)"}`}}>
          {chip}
        </span>
      ))}
    </div>
    <div className="f-mono" style={{fontSize:11,color:"rgba(130,160,185,.5)",lineHeight:1.65}}>
      {meta.helper}
    </div>
  </motion.button>
);

const DataTicker = () => {
  const items="THREAT DB UPDATED 03:24:11 UTC  ◆  247,832 PHISHING DOMAINS TRACKED  ◆  AI MODEL v2.4.1  ◆  LATENCY 12ms  ◆  UPTIME 99.98%  ◆  NEW VECTOR: BEC CAMPAIGN DETECTED  ◆  LAST SCAN: 0.3s AGO  ◆  ";
  return (<div style={{borderTop:"1px solid rgba(0,229,255,.08)",borderBottom:"1px solid rgba(0,229,255,.08)",background:"rgba(0,229,255,.02)",padding:"8px 0",overflow:"hidden",position:"relative",zIndex:5}}><div style={{position:"absolute",left:0,top:0,bottom:0,width:60,background:"linear-gradient(to right,#020812,transparent)",zIndex:2}}/><div style={{position:"absolute",right:0,top:0,bottom:0,width:60,background:"linear-gradient(to left,#020812,transparent)",zIndex:2}}/><div className="ticker-content f-mono" style={{color:"rgba(0,229,255,.35)",fontSize:11,letterSpacing:1.7}}>{items+items}</div></div>);
};

/* ═══════════════════════════════════════════════════════════════
   DEMO DATA
═══════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════
   LANDING PAGE COMPONENTS
═══════════════════════════════════════════════════════════════ */
const EMPTY_ANALYSIS = {
  analysisType: "email",
  classificationLabel: "SUSPICIOUS",
  inputSource: "uploaded_email",
  headerContextAvailable: true,
  verdict: "SUSPICIOUS",
  confidence: 0,
  spamProb: 0,
  riskScore: 0,
  phishScore: 0,
  languageRisk: 0,
  target: "",
  detailTitle: "EMAIL THREAT",
  modelResults: [],
  features: {},
  summary: [],
  sourceDir: "",
  threats: [],
  headers: {
    from: "N/A",
    replyTo: "N/A",
    returnPath: "N/A",
    spf: "N/A",
    dkim: "N/A",
    dmarc: "N/A",
    domain: "N/A",
  },
  urls: [],
  attach: [],
  kw: [],
  stats: { links: 0, html: false, attach: 0, phishKw: 0 },
};

const ANALYZER_MODES = [
  { id: "email", label: "EMAIL", icon: "✉️" },
  { id: "text", label: "TEXT", icon: "📝" },
  { id: "url", label: "URL", icon: "🌐" },
  { id: "file", label: "FILE", icon: "🧩" },
];

const MODEL_META = {
  email: {
    title: "Email Intelligence",
    shortTitle: "EMAIL",
    icon: "✉️",
    accent: "#00E5FF",
    accentSoft: "rgba(0,229,255,.18)",
    glow: "rgba(0,229,255,.16)",
    description: "Analyze uploaded email files with the Week-6 model, header forensics, URL extraction, language heuristics, and attachment signals.",
    source: "WEEK-6 / spam_model.joblib",
    helper: "Use this page to inspect uploaded .eml, .msg, or .txt email files.",
    chips: ["WEEK-6 Model", "Header Analysis", "URL Extraction"],
  },
  text: {
    title: "Text Email Analysis",
    shortTitle: "TEXT",
    icon: "📝",
    accent: "#7C3AED",
    accentSoft: "rgba(124,58,237,.18)",
    glow: "rgba(124,58,237,.16)",
    description: "Analyze pasted email subject and body text through the analyze-text endpoint to return spam probability, language signals, and lightweight forensics.",
    source: "FastAPI / analyze-text",
    helper: "Use this page when you only have the subject and body and need a quick text-only review.",
    chips: ["Manual Input", "Subject + Body", "Language Signals"],
  },
  url: {
    title: "URL Reputation",
    shortTitle: "URL",
    icon: "🌐",
    accent: "#00FFA3",
    accentSoft: "rgba(0,255,163,.18)",
    glow: "rgba(0,255,163,.16)",
    description: "Analyze suspicious links with the models stored in URL/models and review ensemble votes, lexical features, and the final risk summary.",
    source: "URL / models",
    helper: "Use this page for a fast scan of a URL, domain, redirect path, or suspicious link.",
    chips: ["URL Models", "Lexical Features", "Model Ensemble"],
  },
  file: {
    title: "File Malware",
    shortTitle: "FILE",
    icon: "🧩",
    accent: "#FF4D6D",
    accentSoft: "rgba(255,77,109,.18)",
    glow: "rgba(255,77,109,.16)",
    description: "Analyze executable files with the models in FILE/models, extract PE features, and compare malware versus benign votes.",
    source: "FILE / models",
    helper: "Use this page for suspicious .exe, .dll, .scr, .msi, and other PE-format files.",
    chips: ["PE Features", "Malware Vote", "Static Analysis"],
  },
};

const TOPIC_PAGES = [
  { id: "email", label: "EMAIL", accent: "#00E5FF" },
  { id: "text", label: "TEXT", accent: "#7C3AED" },
  { id: "url", label: "URL", accent: "#00FFA3" },
  { id: "file", label: "FILE", accent: "#FF4D6D" },
];

const normalizeVerdict = (verdict) => {
  const key = String(verdict || "").trim().toUpperCase();
  if (!key) return "SUSPICIOUS";
  if (["HAM", "SAFE", "LEGITIMATE", "LEGIT"].includes(key)) return "HAM";
  if (["SUSPICIOUS", "REVIEW"].includes(key)) return "SUSPICIOUS";
  if (["THREAT", "MALICIOUS"].includes(key)) return "THREAT";
  if (["SPAM"].includes(key)) return "SPAM";
  return "SUSPICIOUS";
};

const toPercent = (value) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  if (n <= 1) return Math.max(0, Math.min(100, Math.round(n * 100)));
  return Math.max(0, Math.min(100, Math.round(n)));
};

const toScore = (value) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
};

const normalizeAuthStatus = (value) => {
  const key = String(value || "").trim().toLowerCase();
  if (key === "pass") return "pass";
  if (key === "fail") return "fail";
  if (["softfail", "neutral", "temperror", "permerror"].includes(key)) return "warn";
  if (["none", "n/a", "na", ""].includes(key)) return "na";
  return "na";
};

const authToLabel = (value) => {
  const status = normalizeAuthStatus(value);
  if (status === "pass") return "PASS";
  if (status === "fail") return "FAIL";
  if (status === "warn") return "WARN";
  return "N/A";
};

const urlKey = (url) =>
  String(url || "")
    .trim()
    .toLowerCase()
    .replace(/\/+$/, "");

const deriveAttachmentExt = (filename) => {
  const match = String(filename || "").match(/(\.[a-z0-9]{1,8})$/i);
  return match ? match[1].toLowerCase() : "";
};

const classifyHeaderDomain = (headerFlags, domainAlignmentRaw) => {
  const alignment = String(domainAlignmentRaw || "").toLowerCase();
  if (alignment.includes("align")) return "ALIGNED";
  if (alignment.includes("mismatch")) return "MISMATCH";
  if (alignment.includes("unknown") || alignment.includes("n/a") || alignment.includes("na")) return "UNKNOWN";
  const hasMismatch = headerFlags.some((flag) =>
    /differs from sender domain/i.test(flag),
  );
  return hasMismatch ? "MISMATCH" : "UNKNOWN";
};

const TRUSTED_DOMAIN_SUFFIXES = [
  "google.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "paypal.com",
  "github.com",
  "outlook.com",
  "gmail.com",
];

const REDIRECT_DOMAIN_SUFFIXES = ["bit.ly", "tinyurl.com", "t.co", "lnkd.in", "c.gle", "mailchi.mp"];

const extractUrlDomain = (url) => {
  try {
    return new URL(String(url)).hostname.toLowerCase();
  } catch {
    return "";
  }
};

const domainMatchesAnySuffix = (domain, suffixes) =>
  suffixes.some((suffix) => domain === suffix || domain.endsWith(`.${suffix}`));

const classifyUrlType = (url, suspicious, tracking) => {
  const domain = extractUrlDomain(url);
  if (suspicious) return { type: "Suspicious", domain, tone: "bad" };
  if (tracking && domainMatchesAnySuffix(domain, TRUSTED_DOMAIN_SUFFIXES)) {
    return { type: "Trusted Redirect", domain, tone: "warn" };
  }
  if (tracking) return { type: "Tracking", domain, tone: "warn" };
  if (domainMatchesAnySuffix(domain, REDIRECT_DOMAIN_SUFFIXES)) {
    return { type: "Redirect", domain, tone: "warn" };
  }
  if (domainMatchesAnySuffix(domain, TRUSTED_DOMAIN_SUFFIXES)) {
    return { type: "Trusted", domain, tone: "pass" };
  }
  return { type: "Unknown", domain, tone: "na" };
};

const mapEmailApiResponseToView = (payload) => {
  const headerAnalysis =
    payload && typeof payload.header_analysis === "object" ? payload.header_analysis : {};
  const languageAnalysis =
    payload && typeof payload.language_analysis === "object" ? payload.language_analysis : {};
  const headerFlags = Array.isArray(payload?.header_flags)
    ? payload.header_flags
    : [];
  const headerWarnings = Array.isArray(headerAnalysis?.header_warnings)
    ? headerAnalysis.header_warnings
    : Array.isArray(payload?.header_warnings)
      ? payload.header_warnings
      : [];
  const languageFlags = Array.isArray(payload?.language_flags)
    ? payload.language_flags
    : [];
  const suspiciousIndicators = Array.isArray(languageAnalysis?.suspicious_indicators)
    ? languageAnalysis.suspicious_indicators
    : [];
  const extractedUrls = Array.isArray(payload?.extracted_urls)
    ? payload.extracted_urls
    : [];
  const suspiciousUrls = new Set(
    (Array.isArray(payload?.suspicious_urls) ? payload.suspicious_urls : []).map(
      (url) => urlKey(url),
    ),
  );
  const trackingUrls = new Set(
    (Array.isArray(payload?.tracking_urls) ? payload.tracking_urls : []).map(
      (url) => urlKey(url),
    ),
  );
  const attachmentNames = Array.isArray(payload?.attachment_names)
    ? payload.attachment_names
    : [];
  const attachmentExtensions = Array.isArray(payload?.attachment_extensions)
    ? payload.attachment_extensions
    : [];
  const indicators = Array.isArray(payload?.indicators) ? payload.indicators : [];
  const phishingHits = Array.isArray(languageAnalysis?.phishing_hits)
    ? languageAnalysis.phishing_hits
    : [];
  const mergedHeaderFlags = [...headerFlags, ...headerWarnings];
  const replyToMismatch = mergedHeaderFlags.some((flag) =>
    /reply-to domain differs from sender domain/i.test(flag),
  );
  const spfRaw = headerAnalysis?.spf_status ?? payload?.spf_status ?? "n/a";
  const dkimRaw = headerAnalysis?.dkim_status ?? payload?.dkim_status ?? "n/a";
  const dmarcRaw = headerAnalysis?.dmarc_status ?? payload?.dmarc_status ?? "n/a";
  const domain = classifyHeaderDomain(mergedHeaderFlags, headerAnalysis?.domain_alignment ?? payload?.domain_alignment);
  const filteredLanguageSignals = (suspiciousIndicators.length ? suspiciousIndicators : languageFlags).filter(
    (x) => typeof x === "string" && !/^No strong phishing/i.test(x),
  );
  const languageRiskScore = toPercent(
    languageAnalysis?.language_risk_score ?? payload?.language_risk_score ?? 0,
  );
  const phishingLanguageScore = toPercent(
    languageAnalysis?.phishing_language_score ?? payload?.phishing_language_score ?? 0,
  );

  return {
    analysisType: "email",
    classificationLabel: payload?.classification_label ?? normalizeVerdict(payload?.verdict),
    inputSource: payload?.input_source || "uploaded_email",
    headerContextAvailable: payload?.header_context_available !== false,
    target: payload?.filename || payload?.subject || "manual-input",
    detailTitle: payload?.asset_type_label ?? "EMAIL THREAT",
    modelResults: [],
    features: {},
    summary: Array.isArray(payload?.threat_reasoning) ? payload.threat_reasoning : [],
    sourceDir: payload?.source_dir ?? "",
    verdict: normalizeVerdict(payload?.verdict),
    confidence: toPercent(payload?.confidence),
    spamProb: toPercent(payload?.spam_probability),
    riskScore: toScore(payload?.risk_score),
    phishScore: phishingLanguageScore,
    threats: indicators.filter((x) => typeof x === "string" && x.trim()).slice(0, 8),
    headers: {
      from: headerAnalysis?.from_address ?? payload?.sender ?? "N/A",
      replyTo: headerAnalysis?.reply_to ?? payload?.reply_to ?? "N/A",
      returnPath: headerAnalysis?.return_path ?? payload?.return_path ?? "N/A",
      spf: authToLabel(spfRaw),
      dkim: authToLabel(dkimRaw),
      dmarc: authToLabel(dmarcRaw),
      spfStatus: normalizeAuthStatus(spfRaw),
      dkimStatus: normalizeAuthStatus(dkimRaw),
      dmarcStatus: normalizeAuthStatus(dmarcRaw),
      domain,
      replyToMismatch,
      warnings: mergedHeaderFlags,
    },
    urls: extractedUrls.map((url) => {
      const key = urlKey(url);
      const suspicious = suspiciousUrls.has(key);
      const tracking = trackingUrls.has(key);
      const classified = classifyUrlType(url, suspicious, tracking);
      return {
        url,
        domain: classified.domain || "n/a",
        sus: suspicious,
        tone: classified.tone,
        type: classified.type,
      };
    }),
    attach: attachmentNames.map((name, idx) => {
      const ext = String(attachmentExtensions[idx] || deriveAttachmentExt(name)).toLowerCase();
      const riskyExec = [
        ".exe",
        ".js",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
      ].includes(ext);
      const riskyMacro = [".docm", ".xlsm"].includes(ext);
      const riskyCompressed = [".zip", ".rar", ".7z"].includes(ext);
      const danger = riskyExec || riskyMacro || riskyCompressed;
      const reason = riskyExec
        ? "Executable script/binary extension detected."
        : riskyMacro
          ? "Macro-enabled Office extension detected."
          : riskyCompressed
            ? "Compressed attachment detected. Review content."
            : "No risky extension detected.";
      return { name, ext, danger, reason };
    }),
    kw: filteredLanguageSignals,
    languageRisk: languageRiskScore,
    stats: {
      links: Number(payload?.url_count || extractedUrls.length || 0),
      html: Boolean(payload?.has_html),
      attach: Number(payload?.attachment_count || attachmentNames.length || 0),
      phishKw: phishingHits.length,
    },
  };
};

const humanizeFeatureKey = (key) =>
  String(key || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());

const formatFeatureValue = (value) => {
  if (typeof value === "number") {
    return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(6).replace(/0+$/, "").replace(/\.$/, "");
  }
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (value === null || value === undefined || value === "") return "N/A";
  return String(value);
};

const formatPercentLabel = (value, digits = 0) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return "N/A";
  return `${n.toFixed(digits)}%`;
};

const formatFileSize = (bytes) => {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return "N/A";
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  return `${(n / 1024).toFixed(1)} KB`;
};

const mapAssetApiResponseToView = (payload) => {
  const analysisType = String(payload?.analysis_type || "file").toLowerCase();
  const modelResults = Array.isArray(payload?.model_results) ? payload.model_results : [];
  const features = payload && typeof payload.features === "object" ? payload.features : {};
  const summary = Array.isArray(payload?.summary) ? payload.summary : [];
  const harmfulVotes = Number(payload?.harmful_votes || 0);
  const modelCount = Number(payload?.model_count || modelResults.length || 0);
  const votePercent = modelCount ? Math.round((harmfulVotes / modelCount) * 100) : 0;
  const primaryThreats = summary.filter((item) => typeof item === "string" && item.trim()).slice(0, 8);
  const scoreBreakdown = payload && typeof payload.score_breakdown === "object" ? payload.score_breakdown : {};

  return {
    analysisType,
    classificationLabel: payload?.classification_label || (harmfulVotes > 0 ? "THREAT" : "BENIGN"),
    inputSource: payload?.input_source || analysisType,
    headerContextAvailable: true,
    verdict: normalizeVerdict(payload?.verdict),
    confidence: toPercent(payload?.confidence),
    spamProb: votePercent,
    riskScore: toScore(payload?.risk_score),
    phishScore: 0,
    languageRisk: 0,
    target: payload?.target || "",
    detailTitle: payload?.asset_type_label || (analysisType === "url" ? "URL REPUTATION" : "FILE MALWARE"),
    modelResults: modelResults.map((item) => ({
      model: item?.model || "unknown",
      prediction: item?.prediction || "N/A",
      confidence: item?.confidence == null ? null : toPercent(item.confidence),
      isMalicious: Boolean(item?.is_malicious),
    })),
    features,
    summary,
    sourceDir: payload?.source_dir || "",
    scoreBreakdown: {
      harmfulVotes: Number(scoreBreakdown?.harmful_votes || harmfulVotes),
      totalModels: Number(scoreBreakdown?.total_models || modelCount),
      harmfulVotePercent: Number(scoreBreakdown?.harmful_vote_percent || votePercent),
      confidencePercent: Number(scoreBreakdown?.confidence_percent || 0),
      voteWeightPercent: Number(scoreBreakdown?.vote_weight_percent || 70),
      confidenceWeightPercent: Number(scoreBreakdown?.confidence_weight_percent || 30),
      voteComponentPercent: Number(scoreBreakdown?.vote_component_percent || 0),
      confidenceComponentPercent: Number(scoreBreakdown?.confidence_component_percent || 0),
      riskBeforeAdjustment: Math.max(0, Math.min(100, Number(scoreBreakdown?.risk_before_adjustment ?? payload?.risk_score ?? 0))),
      trustAdjustmentFactor: Number(scoreBreakdown?.trust_adjustment_factor || 1),
      riskAfterAdjustment: Math.max(0, Math.min(100, Number(scoreBreakdown?.risk_after_adjustment ?? payload?.risk_score ?? 0))),
    },
    threats: primaryThreats,
    headers: { ...EMPTY_ANALYSIS.headers },
    urls: analysisType === "url" && payload?.target
      ? [{ url: payload.target, domain: extractUrlDomain(payload.target) || "n/a", sus: harmfulVotes > 0, tone: harmfulVotes > 0 ? "bad" : "pass", type: harmfulVotes > 0 ? "Suspicious" : "Checked" }]
      : [],
    attach: analysisType === "file" && payload?.target
      ? [{ name: payload.target, ext: deriveAttachmentExt(payload.target), danger: harmfulVotes > 0, reason: harmfulVotes > 0 ? "One or more malware models flagged this file." : "No malware model flagged this file." }]
      : [],
    kw: summary,
    stats: {
      links: analysisType === "url" ? 1 : 0,
      html: false,
      attach: analysisType === "file" ? 1 : 0,
      phishKw: 0,
    },
  };
};

const mapApiResponseToView = (payload) =>
  String(payload?.analysis_type || "email").toLowerCase() === "email"
    ? mapEmailApiResponseToView(payload)
    : mapAssetApiResponseToView(payload);

const LandingTicker = () => {
  const items=["⬡ 2.4B THREATS BLOCKED TODAY","◈ 99.97% DETECTION RATE","◆ <0.3ms SCAN LATENCY","⬡ 140+ THREAT VECTORS","◈ SOC2 TYPE II CERTIFIED","◆ ZERO TRUST ARCHITECTURE","⬡ AI-POWERED ENGINE","◈ REAL-TIME INTELLIGENCE","◆ 50M+ EMAILS SCANNED","⬡ ENTERPRISE GRADE"];
  const str=items.join("    ");
  return (<div style={{overflow:"hidden",borderTop:"1px solid rgba(0,255,65,.1)",borderBottom:"1px solid rgba(0,255,65,.1)",background:"rgba(0,255,65,.02)",padding:"12px 0",position:"relative",zIndex:10}}><div style={{display:"flex",whiteSpace:"nowrap",animation:"ticker 40s linear infinite"}}>{[str,str].map((s,i)=>(<span key={i} className="f-mono" style={{color:"rgba(0,255,65,.56)",fontSize:11,letterSpacing:2.2,paddingRight:40}}>{s}</span>))}</div></div>);
};
const Counter = ({target,suffix="",label,color="#00FF41"}) => {
  const fmt=n=>{if(n>=1e9)return(n/1e9).toFixed(1)+"B";if(n>=1e6)return(n/1e6).toFixed(0)+"M";if(n>=1e3)return(n/1e3).toFixed(0)+"K";return n.toLocaleString();};
  return (<div style={{textAlign:"center",padding:"34px 16px",borderRight:"1px solid rgba(0,255,65,.06)"}}><div className="f-orb" style={{fontSize:"clamp(30px,3vw,46px)",fontWeight:900,color,lineHeight:1,letterSpacing:-1}}>{fmt(target)}{suffix}</div><div className="f-mono" style={{color:"rgba(200,220,238,.58)",fontSize:12,letterSpacing:2.2,marginTop:12,textTransform:"uppercase"}}>{label}</div></div>);
};
const FeatureCard = ({icon,title,desc,color="#00FF41",delay=0}) => {
  const [hov,setHov]=useState(false);
  const col=color==="red"?"255,60,60":color==="#00E5FF"?"0,229,255":"0,255,65";
  return (<div onMouseEnter={()=>setHov(true)} onMouseLeave={()=>setHov(false)} style={{padding:"34px 30px",borderRadius:8,cursor:"none",background:hov?`rgba(${col},.06)`:"rgba(0,255,65,.025)",border:`1px solid rgba(${col},${hov?.25:.1})`,transition:"all .35s ease",boxShadow:hov?`0 8px 40px rgba(${col},.08)`:"none"}}><div style={{width:48,height:48,borderRadius:10,background:`rgba(${col},.1)`,border:`1px solid rgba(${col},.25)`,display:"flex",alignItems:"center",justifyContent:"center",marginBottom:22,fontSize:22}}>{icon}</div><div className="f-orb" style={{color:color==="red"?"#FF6060":color==="#00E5FF"?"#00E5FF":"#00FF41",fontSize:15,fontWeight:700,letterSpacing:1.6,marginBottom:14}}>{title}</div><div style={{color:"rgba(200,220,238,.66)",fontSize:15,lineHeight:1.8}}>{desc}</div></div>);
};
const PricingCard = ({tier,price,period="/mo",features,highlight=false,delay=0,onStart}) => {
  const [hov,setHov]=useState(false);
  return (<div className="fade-in" onMouseEnter={()=>setHov(true)} onMouseLeave={()=>setHov(false)} style={{padding:"36px 28px",borderRadius:8,cursor:"none",position:"relative",background:highlight?"rgba(0,255,65,.06)":"rgba(0,20,8,.6)",border:highlight?"1px solid rgba(0,255,65,.35)":"1px solid rgba(0,255,65,.1)",boxShadow:highlight?"0 0 60px rgba(0,255,65,.1),inset 0 0 40px rgba(0,255,65,.03)":"none",transform:(highlight||hov)?"translateY(-6px)":"translateY(0)",transition:"all .35s ease"}}>{highlight&&<div className="f-mono" style={{position:"absolute",top:-12,left:"50%",transform:"translateX(-50%)",background:"#00FF41",color:"#020812",padding:"4px 16px",borderRadius:99,fontSize:9,fontWeight:700,letterSpacing:2}}>MOST POPULAR</div>}<div className="f-mono" style={{color:"rgba(0,255,65,.6)",fontSize:10,letterSpacing:3,textTransform:"uppercase",marginBottom:8}}>{tier}</div><div style={{display:"flex",alignItems:"baseline",gap:4,marginBottom:24}}><span className="f-orb" style={{fontSize:42,fontWeight:900,color:highlight?"#00FF41":"#C8DCEE"}}>${price}</span><span className="f-mono" style={{color:"rgba(200,220,238,.4)",fontSize:12}}>{period}</span></div><div style={{borderTop:"1px solid rgba(0,255,65,.1)",paddingTop:24,display:"flex",flexDirection:"column",gap:14}}>{features.map((f,i)=>(<div key={i} style={{display:"flex",alignItems:"center",gap:10}}><span style={{color:"#00FF41",fontSize:10}}>◆</span><span className="f-mono" style={{color:"rgba(200,220,238,.7)",fontSize:12}}>{f}</span></div>))}</div><button className="f-orb" onClick={onStart} style={{width:"100%",marginTop:28,padding:"12px",borderRadius:4,fontSize:11,fontWeight:700,letterSpacing:2,cursor:"none",background:highlight?"rgba(0,255,65,.15)":"transparent",border:highlight?"1px solid rgba(0,255,65,.5)":"1px solid rgba(0,255,65,.2)",color:highlight?"#00FF41":"rgba(0,255,65,.6)",transition:"all .25s"}} onMouseEnter={e=>{e.target.style.background="rgba(0,255,65,.25)";e.target.style.boxShadow="0 0 20px rgba(0,255,65,.15)";}} onMouseLeave={e=>{e.target.style.background=highlight?"rgba(0,255,65,.15)":"transparent";e.target.style.boxShadow="none";}}>GET STARTED</button></div>);
};
const Step=({num,title,desc,delay=0})=>(<div className="fade-in" style={{display:"flex",gap:24,alignItems:"flex-start",animationDelay:delay+"s"}}><div style={{flexShrink:0,width:56,height:56,borderRadius:"50%",border:"1px solid rgba(0,255,65,.3)",display:"flex",alignItems:"center",justifyContent:"center",background:"rgba(0,255,65,.06)"}}><span className="f-orb" style={{color:"#00FF41",fontSize:18,fontWeight:700}}>{num}</span></div><div><div className="f-orb" style={{color:"#00FF41",fontSize:15,fontWeight:700,letterSpacing:1.1,marginBottom:10}}>{title}</div><div style={{color:"rgba(200,220,238,.66)",fontSize:15,lineHeight:1.8}}>{desc}</div></div></div>);
const Testimonial=({quote,name,role,company,delay=0})=>(<div className="fade-in glass-lp" style={{padding:"28px",borderRadius:8}}><div style={{color:"rgba(0,255,65,.4)",fontSize:32,lineHeight:1,marginBottom:16,fontFamily:"serif"}}>"</div><div style={{color:"rgba(200,220,238,.8)",fontSize:14,lineHeight:1.75,marginBottom:20}}>{quote}</div><div style={{borderTop:"1px solid rgba(0,255,65,.1)",paddingTop:16}}><div className="f-orb" style={{color:"#00FF41",fontSize:12,fontWeight:600}}>{name}</div><div className="f-mono" style={{color:"rgba(200,220,238,.4)",fontSize:10,letterSpacing:1,marginTop:2}}>{role} · {company}</div></div></div>);


/* ═══════════════════════════════════════════════════════════════
   UNIFIED NAV
═══════════════════════════════════════════════════════════════ */
const Nav = ({page, setPage, scrollY}) => {
  const scrolled = scrollY > 60;
  const isAppLike = page !== "landing";
  return (
    <motion.nav style={{position:"fixed",top:0,left:0,right:0,zIndex:1000,padding:"0 5%",height:70,display:"flex",alignItems:"center",justifyContent:"space-between",background:isAppLike?"rgba(2,8,18,.95)":scrolled?"rgba(2,8,18,.88)":"transparent",borderBottom:scrolled||isAppLike?"1px solid rgba(0,255,65,.1)":"1px solid transparent",backdropFilter:scrolled||isAppLike?"blur(18px)":"none",transition:"all .4s ease"}}>
      <div style={{display:"flex",alignItems:"center",gap:10,cursor:"none"}} onClick={()=>setPage("landing")}>
        <div style={{width:32,height:32,borderRadius:6,border:"1px solid rgba(0,255,65,.4)",display:"flex",alignItems:"center",justifyContent:"center",background:"rgba(0,255,65,.08)"}}>
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="#00FF41" strokeWidth="1"/><circle cx="8" cy="8" r="3" stroke="#00FF41" strokeWidth="1" opacity=".5"/><line x1="8" y1="2" x2="8" y2="8" stroke="#00FF41" strokeWidth="1.5"/></svg>
        </div>
        <span className="f-orb" style={{color:"#00FF41",fontWeight:700,fontSize:18,letterSpacing:2.4}}>SENTINEL</span>
        <span className="f-mono" style={{color:"rgba(0,255,65,.4)",fontSize:10,letterSpacing:1.2,marginTop:2}}>v2.0</span>
      </div>
      <div style={{display:"flex",gap:8,alignItems:"center"}}>
        <button onClick={()=>setPage("landing")} className="f-mono" style={{background:"transparent",border:"1px solid rgba(0,255,65,.3)",color:page==="landing"?"#00FF41":"rgba(0,255,65,.7)",padding:"9px 14px",borderRadius:4,fontSize:12,letterSpacing:1.1,cursor:"none",transition:"all .2s"}} onMouseEnter={e=>e.currentTarget.style.borderColor="rgba(0,255,65,.7)"} onMouseLeave={e=>e.currentTarget.style.borderColor="rgba(0,255,65,.3)"}>HOME</button>
        {TOPIC_PAGES.map(({ id, label, accent }) => (
          <button
            key={id}
            onClick={() => setPage(id)}
            className="f-mono"
            style={{background:page===id?`${accent}16`:"transparent",border:`1px solid ${page===id?accent:"rgba(200,220,238,.12)"}`,color:page===id?accent:"rgba(200,220,238,.7)",padding:"9px 14px",borderRadius:4,fontSize:12,letterSpacing:1.1,cursor:"none",transition:"all .2s"}}
          >
            {label}
          </button>
        ))}
        <button onClick={()=>setPage("dashboard")} className="f-mono" style={{background:page==="dashboard"?"rgba(0,229,255,.12)":"transparent",border:"1px solid rgba(0,229,255,.25)",color:page==="dashboard"?"#00E5FF":"rgba(0,229,255,.82)",padding:"9px 14px",borderRadius:4,fontSize:12,letterSpacing:1.1,cursor:"none",transition:"all .2s"}} onMouseEnter={e=>e.currentTarget.style.borderColor="rgba(0,229,255,.55)"} onMouseLeave={e=>e.currentTarget.style.borderColor="rgba(0,229,255,.25)"}>DASHBOARD</button>
        {isAppLike && (
          <div style={{display:"flex",alignItems:"center",gap:6,padding:"6px 14px",borderRadius:6,background:"rgba(0,229,255,.05)",border:"1px solid rgba(0,229,255,.18)"}}>
            <div style={{width:6,height:6,borderRadius:"50%",background:"#00FFA3",boxShadow:"0 0 6px #00FFA3",animation:"pulse-ring 2s ease-in-out infinite"}}/>
            <span className="f-mono" style={{fontSize:10,color:"rgba(0,255,163,.7)",letterSpacing:1.2}}>ONLINE</span>
          </div>
        )}
      </div>
    </motion.nav>
  );
};

/* ═══════════════════════════════════════════════════════════════
   LANDING PAGE
═══════════════════════════════════════════════════════════════ */
const LandingPage = ({mx, my, setPage}) => (
  <div style={{position:"relative",zIndex:1}}>
    <section style={{minHeight:"100vh",display:"flex",alignItems:"center",padding:"80px 5% 40px"}}>
      <div style={{flex:1,maxWidth:560}}>
        <motion.div initial={{opacity:0,y:20}} animate={{opacity:1,y:0}} transition={{duration:.6}} className="f-mono" style={{color:"rgba(0,255,65,.6)",fontSize:12,letterSpacing:3.2,marginBottom:22,display:"flex",alignItems:"center",gap:8}}>
          <span style={{width:6,height:6,borderRadius:"50%",background:"#00FF41",display:"inline-block",animation:"blink 1.2s ease-in-out infinite"}}/>
          MULTI-TOPIC ANALYSIS WORKSPACE
        </motion.div>
        <motion.h1 initial={{opacity:0,y:30}} animate={{opacity:1,y:0}} transition={{duration:.7,delay:.1}} className="f-orb" style={{fontSize:"clamp(36px,4.5vw,62px)",fontWeight:900,lineHeight:1.1,letterSpacing:-1,marginBottom:24}}>
          <span style={{color:"#C8DCEE"}}>Choose one topic</span><br/>
          <span className="shimmer-text">and analyze deeply</span>
        </motion.h1>
        <motion.p initial={{opacity:0,y:20}} animate={{opacity:1,y:0}} transition={{duration:.6,delay:.2}} style={{color:"rgba(200,220,238,.7)",fontSize:18,lineHeight:1.8,marginBottom:38,maxWidth:520}}>
          The frontend is now split into dedicated pages for email files, pasted email text, suspicious URLs, and executable files. Each topic has its own focused input flow instead of a combined analyzer screen.
        </motion.p>
        <motion.div initial={{opacity:0,y:20}} animate={{opacity:1,y:0}} transition={{duration:.6,delay:.3}} style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(220px,1fr))",gap:14}}>
          {[...TOPIC_PAGES, { id: "dashboard", label: "DASHBOARD", accent: "#00E5FF" }].map((item) => (
            <button
              key={item.id}
              onClick={() => setPage(item.id)}
              className="glass-card"
              style={{padding:"18px 20px",textAlign:"left",border:`1px solid ${item.accent}33`,cursor:"none",background:`linear-gradient(135deg, ${item.accent}10, rgba(4,10,22,.94))`,transition:"all .25s"}}
            >
              <div className="f-mono" style={{fontSize:11,color:item.accent,letterSpacing:2.1}}>{item.label}</div>
              <div className="f-syne" style={{fontSize:14,color:"rgba(200,220,238,.7)",lineHeight:1.7,marginTop:10}}>
                {item.id==="email" ? "Upload .eml or email files for full forensic analysis."
                  : item.id==="text" ? "Paste subject and body text for quick email screening."
                  : item.id==="url" ? "Scan one suspicious link with the URL models."
                  : item.id==="file" ? "Upload executable files for malware-oriented static checks."
                  : "Open the chart-only page for D3 telemetry and mock analytics."}
              </div>
            </button>
          ))}
        </motion.div>
      </div>
      <motion.div initial={{opacity:0,scale:.9}} animate={{opacity:1,scale:1}} transition={{duration:.8,delay:.2}} style={{flex:1,display:"flex",justifyContent:"center",alignItems:"center",minWidth:0,overflow:"hidden"}}>
        <div style={{transform:"scale(0.72)",transformOrigin:"center center"}}><ThreatRadar mx={mx} my={my}/></div>
      </motion.div>
    </section>
    <LandingTicker/>
  </div>
);

/* ═══════════════════════════════════════════════════════════════
   ANALYZER APP PAGE
═══════════════════════════════════════════════════════════════ */
const AnalyzerApp = ({topic}) => {
  const [file,setFile]=useState(null);
  const [subj,setSubj]=useState("");
  const [body,setBody]=useState("");
  const [urlValue,setUrlValue]=useState("");
  const [drag,setDrag]=useState(false);
  const [focused,setFocused]=useState(false);
  const [phase,setPhase]=useState("idle");
  const [analysis,setAnalysis]=useState(EMPTY_ANALYSIS);
  const [error,setError]=useState("");
  const activeMeta = MODEL_META[topic];
  const canScan = topic==="email"
    ? Boolean(file)
    : topic==="text"
      ? body.trim().length>5 || subj.trim().length>0
      : topic==="url"
        ? urlValue.trim().length>3
        : Boolean(file);
  const scanLabel = topic==="url" ? "ANALYZE URL" : topic==="file" ? "ANALYZE FILE" : topic==="text" ? "ANALYZE TEXT" : "ANALYZE EMAIL";
  const inputTitle = topic==="url" ? "URL INPUT" : topic==="file" ? "FILE INPUT" : topic==="text" ? "TEXT INPUT" : "EMAIL INPUT";
  const inputMeta = topic==="url"
    ? "PASTE ONE URL"
    : topic==="file"
      ? "MAX 100MB · .EXE .DLL .SCR .MSI"
      : topic==="text"
        ? "SUBJECT + BODY"
        : "MAX 100MB · .EML .MSG .TXT";

  const analyze=async()=>{
    if(!canScan) return;
    setError("");
    setPhase("scanning");
    try{
      let response;
      if(topic==="email"){
        const form=new FormData();
        form.append("file",file);
        response=await fetch(`${API_BASE}/analyze-email`,{method:"POST",body:form});
      }else if(topic==="text"){
        response=await fetch(`${API_BASE}/analyze-text`,{
          method:"POST",
          headers:{"Content-Type":"application/json"},
          body:JSON.stringify({subject:subj,body}),
        });
      }else if(topic==="url"){
        response=await fetch(`${API_BASE}/analyze-url`,{
          method:"POST",
          headers:{"Content-Type":"application/json"},
          body:JSON.stringify({url:urlValue}),
        });
      }else{
        const form=new FormData();
        form.append("file",file);
        response=await fetch(`${API_BASE}/analyze-file`,{method:"POST",body:form});
      }
      if(!response.ok){
        const errPayload=await response.json().catch(()=>({}));
        const detail=typeof errPayload?.detail==="string"?errPayload.detail:`Request failed (${response.status})`;
        throw new Error(detail);
      }
      const payload=await response.json();
      setAnalysis(mapApiResponseToView(payload));
      setPhase("result");
    }catch(e){
      console.error("Analyze failed",e);
      const msg=String(e?.message||"");
      const isNetworkError=e instanceof TypeError||/networkerror|failed to fetch/i.test(msg);
      if(isNetworkError){
        setError(`Cannot reach backend at ${API_BASE}. Start backend on port 8000 or set VITE_API_BASE_URL.`);
      }else{
        setError(msg||`Could not analyze this ${topic}.`);
      }
      setPhase("idle");
    }
  };
  const reset=()=>{setPhase("idle");setFile(null);setBody("");setSubj("");setUrlValue("");setError("");setAnalysis(EMPTY_ANALYSIS);setDrag(false);setFocused(false);};
  const result=analysis||EMPTY_ANALYSIS;
  const phishScore=toPercent(result.phishScore);
  const languageRisk=toPercent(result.languageRisk);
  const verdictLabelOverride = result.analysisType==="email"
    ? undefined
    : (result.classificationLabel || (result.verdict==="HAM" ? "BENIGN" : result.verdict));
  const verdictSubOverride = result.analysisType==="email"
    ? undefined
    : (result.analysisType==="url" ? "URL ensemble verdict" : "File ensemble verdict");
  const authStatusToRowStatus=(status)=>{
    if(status==="fail") return "bad";
    if(status==="warn") return "warn";
    if(status==="pass") return "pass";
    return "na";
  };
  const headerDomainStatus=result.headers.domain==="MISMATCH"?"bad":result.headers.domain==="ALIGNED"?"pass":"na";
  const replyToStatus=result.headers.replyToMismatch?"warn":result.headers.replyTo==="N/A"?"na":"pass";
  const DRow=({k,v,status})=>{
    const palette=status==="bad"
      ? { text:"#FF4D6D", bg:"rgba(255,77,109,.1)", border:"rgba(255,77,109,.3)", label:"FAIL" }
      : status==="warn"
        ? { text:"#FFD60A", bg:"rgba(255,214,10,.1)", border:"rgba(255,214,10,.3)", label:"WARN" }
        : status==="pass"
          ? { text:"#00FFA3", bg:"rgba(0,255,163,.1)", border:"rgba(0,255,163,.3)", label:"PASS" }
          : { text:"#8A7AAE", bg:"rgba(138,122,174,.08)", border:"rgba(138,122,174,.25)", label:"N/A" };
    return (
      <div style={{display:"flex",gap:10,alignItems:"center",padding:"8px 0",borderBottom:"1px solid rgba(0,229,255,.05)"}}>
        <span className="f-mono" style={{fontSize:11,color:"rgba(100,140,170,.58)",letterSpacing:1.6,minWidth:96}}>{k}</span>
        <span className="f-mono" style={{fontSize:12,color:palette.text,flex:1,wordBreak:"break-all",lineHeight:1.7}}>{v}</span>
        <span className="f-mono" style={{fontSize:10,padding:"4px 9px",borderRadius:4,flexShrink:0,background:palette.bg,border:`1px solid ${palette.border}`,color:palette.text}}>{palette.label}</span>
      </div>
    );
  };

  return (
    <div style={{position:"relative",zIndex:10,maxWidth:920,margin:"0 auto",padding:"80px 24px 120px"}}>
      <DataTicker/>
      {phase==="scanning"&&<ScanLine/>}
      <section style={{textAlign:"center",padding:"40px 0 28px"}}>
        <motion.div initial={{opacity:0,y:32}} animate={{opacity:1,y:0}} transition={{delay:.2,duration:.6}}>
          <div className="f-mono" style={{fontSize:12,color:activeMeta.accent,letterSpacing:5,marginTop:20,marginBottom:14}}>◆ DEDICATED ANALYSIS PAGE ◆</div>
          <h1 className="f-orb" style={{fontSize:"clamp(34px,5vw,52px)",fontWeight:900,lineHeight:1.15,letterSpacing:1}}>
            <span style={{color:"#D0E8F8"}}>{activeMeta.title}</span><br/>
            <span style={{background:`linear-gradient(90deg,${activeMeta.accent} 0%, #00E5FF 100%)`,WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent",filter:`drop-shadow(0 0 20px ${activeMeta.glow})`}}>{activeMeta.shortTitle} WORKFLOW</span>
          </h1>
          <p className="f-syne" style={{color:"rgba(100,140,170,.66)",fontSize:16,margin:"18px auto 0",maxWidth:680,lineHeight:1.9}}>{activeMeta.description}</p>
          <div style={{display:"flex",gap:10,justifyContent:"center",flexWrap:"wrap",marginTop:24}}>
            {activeMeta.chips.map((chip)=>(<div key={chip} className="f-mono" style={{fontSize:11,color:activeMeta.accent,letterSpacing:1.1,padding:"6px 14px",borderRadius:99,background:`${activeMeta.accent}10`,border:`1px solid ${activeMeta.accent}22`}}>{chip}</div>))}
          </div>
        </motion.div>
      </section>

      {/* Input */}
      <AnimatePresence>
        {phase!=="result"&&(
          <motion.section initial={{opacity:0,y:40}} animate={{opacity:1,y:0}} exit={{opacity:0,y:-30,scale:.97}} transition={{delay:.6,duration:.6}}>
            <div className={`glass-card ${focused?"glass-card-glow":""}`} style={{padding:"28px 30px",marginBottom:20,transition:"all .3s",border:`1px solid ${activeMeta.accentSoft}`}}>
              {[{t:0,l:0,bt:"2px solid rgba(0,229,255,.5)",bl:"2px solid rgba(0,229,255,.5)"},{t:0,r:0,bt:"2px solid rgba(0,229,255,.5)",br:"2px solid rgba(0,229,255,.5)"},{b:0,l:0,bb:"2px solid rgba(0,229,255,.5)",bl:"2px solid rgba(0,229,255,.5)"},{b:0,r:0,bb:"2px solid rgba(0,229,255,.5)",br:"2px solid rgba(0,229,255,.5)"}].map((s,i)=>(<div key={i} style={{position:"absolute",width:16,height:16,...s}}/>))}
              <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:22,gap:18,flexWrap:"wrap"}}>
                <div>
                  <div className="f-orb" style={{fontSize:11,color:activeMeta.accent,letterSpacing:3.2}}>{inputTitle}</div>
                  <div className="f-orb" style={{fontSize:24,color:"#D0E8F8",letterSpacing:1,marginTop:10}}>{activeMeta.title}</div>
                  <div className="f-syne" style={{fontSize:15,color:"rgba(180,205,225,.74)",lineHeight:1.85,maxWidth:560,marginTop:10}}>{activeMeta.description}</div>
                </div>
                <div style={{display:"flex",flexDirection:"column",alignItems:"flex-end",gap:10}}>
                  <div className="f-mono" style={{fontSize:11,color:"rgba(100,140,170,.48)",letterSpacing:1.1}}>{inputMeta}</div>
                  <div className="f-mono" style={{fontSize:11,color:activeMeta.accent,letterSpacing:1.3,padding:"7px 11px",borderRadius:999,background:`${activeMeta.accent}10`,border:`1px solid ${activeMeta.accent}2E`}}>
                    SOURCE: {activeMeta.source}
                  </div>
                </div>
              </div>
              <div style={{display:"flex",flexWrap:"wrap",gap:8,marginBottom:18}}>
                {activeMeta.chips.map((chip)=>(<span key={chip} className="f-mono" style={{fontSize:10,color:activeMeta.accent,letterSpacing:1.2,padding:"5px 11px",borderRadius:999,background:`${activeMeta.accent}10`,border:`1px solid ${activeMeta.accent}24`}}>{chip}</span>))}
              </div>
              <AnimatePresence mode="wait">
                {topic==="email"?(
                  <motion.div key="up" initial={{opacity:0,x:-18}} animate={{opacity:1,x:0}} exit={{opacity:0,x:18}} transition={{duration:.2}} onDragOver={e=>{e.preventDefault();setDrag(true);}} onDragLeave={()=>setDrag(false)} onDrop={e=>{e.preventDefault();setDrag(false);const f=e.dataTransfer.files[0];if(f)setFile(f);}} onClick={()=>document.getElementById("fi2").click()} style={{border:`1.5px dashed ${drag?"#00E5FF":file?"#00FFA3":"rgba(0,229,255,.16)"}`,borderRadius:12,padding:"50px 28px",textAlign:"center",cursor:"pointer",background:drag?"rgba(0,229,255,.04)":"rgba(0,0,0,.2)",transition:"all .3s"}}>
                    <input id="fi2" type="file" accept=".eml,.msg,.txt" style={{display:"none"}} onChange={e=>{const f=e.target.files[0];if(f)setFile(f);}}/>
                    <div style={{fontSize:44,marginBottom:14}}>{file?"✅":"📧"}</div>
                    {file?(<><div className="f-mono" style={{color:"#00FFA3",fontSize:16}}>{file.name}</div><div style={{color:"rgba(0,255,163,.5)",fontSize:13,marginTop:6}}>{formatFileSize(file.size)} · Ready for analysis</div></>):(<><div className="f-orb" style={{color:"rgba(100,140,170,.58)",fontSize:13,letterSpacing:3}}>DROP FILE HERE</div><div style={{color:"rgba(100,140,170,.32)",fontSize:13,marginTop:8}}>or click to browse — supports .eml, .msg, .txt</div></>)}
                  </motion.div>
                ):topic==="text"?(
                  <motion.div key="ps" initial={{opacity:0,x:18}} animate={{opacity:1,x:0}} exit={{opacity:0,x:-18}} transition={{duration:.2}}>
                    <div style={{marginBottom:16}}><label className="f-mono" style={{display:"block",fontSize:11,color:"rgba(100,140,170,.58)",letterSpacing:2.2,marginBottom:8}}>SUBJECT LINE</label><input value={subj} onChange={e=>setSubj(e.target.value)} onFocus={()=>setFocused(true)} onBlur={()=>setFocused(false)} placeholder="Re: Urgent — Verify Your Account Immediately" className="cyber-input" style={{padding:"13px 16px",fontSize:15}}/></div>
                    <div><label className="f-mono" style={{display:"block",fontSize:11,color:"rgba(100,140,170,.58)",letterSpacing:2.2,marginBottom:8}}>FULL EMAIL BODY</label><textarea value={body} onChange={e=>setBody(e.target.value)} onFocus={()=>setFocused(true)} onBlur={()=>setFocused(false)} placeholder={"Paste complete email content here...\n\nInclude headers for best analysis results."} rows={9} className="cyber-input" style={{padding:"15px 16px",resize:"vertical",lineHeight:1.8,fontSize:15}}/></div>
                    <div className="f-mono" style={{fontSize:12,color:"rgba(255,214,10,.72)",marginTop:12,lineHeight:1.75}}>Paste mode has less header evidence than a real <span style={{color:"#FFD60A"}}>.eml</span> file, so SPF/DKIM checks may be unavailable.</div>
                  </motion.div>
                ):topic==="url"?(
                  <motion.div key="url" initial={{opacity:0,x:18}} animate={{opacity:1,x:0}} exit={{opacity:0,x:-18}} transition={{duration:.2}}>
                    <div><label className="f-mono" style={{display:"block",fontSize:11,color:"rgba(100,140,170,.58)",letterSpacing:2.2,marginBottom:8}}>TARGET URL</label><input value={urlValue} onChange={e=>setUrlValue(e.target.value)} onFocus={()=>setFocused(true)} onBlur={()=>setFocused(false)} placeholder="https://example.com/login/verify-account" className="cyber-input" style={{padding:"13px 16px",fontSize:15}}/></div>
                    <div className="f-mono" style={{fontSize:12,color:"rgba(100,140,170,.46)",marginTop:12,lineHeight:1.75}}>This API uses the models in <span style={{color:"rgba(0,229,255,.7)"}}>URL/models</span> and returns the vote from each model in the ensemble.</div>
                  </motion.div>
                ):(
                  <motion.div key="file-upload" initial={{opacity:0,x:-18}} animate={{opacity:1,x:0}} exit={{opacity:0,x:18}} transition={{duration:.2}} onDragOver={e=>{e.preventDefault();setDrag(true);}} onDragLeave={()=>setDrag(false)} onDrop={e=>{e.preventDefault();setDrag(false);const f=e.dataTransfer.files[0];if(f)setFile(f);}} onClick={()=>document.getElementById("fi3").click()} style={{border:`1.5px dashed ${drag?"#00E5FF":file?"#FF4D6D":"rgba(0,229,255,.16)"}`,borderRadius:12,padding:"50px 28px",textAlign:"center",cursor:"pointer",background:drag?"rgba(0,229,255,.04)":"rgba(0,0,0,.2)",transition:"all .3s"}}>
                    <input id="fi3" type="file" accept=".exe,.dll,.scr,.msi,.sys,.bat,.cmd,.ps1,.bin" style={{display:"none"}} onChange={e=>{const f=e.target.files[0];if(f)setFile(f);}}/>
                    <div style={{fontSize:44,marginBottom:14}}>{file?"🧩":"📁"}</div>
                    {file?(<><div className="f-mono" style={{color:"#FF4D6D",fontSize:16}}>{file.name}</div><div style={{color:"rgba(255,77,109,.58)",fontSize:13,marginTop:6}}>{formatFileSize(file.size)} · Ready for malware scan</div></>):(<><div className="f-orb" style={{color:"rgba(100,140,170,.58)",fontSize:13,letterSpacing:3}}>DROP EXECUTABLE HERE</div><div style={{color:"rgba(100,140,170,.32)",fontSize:13,marginTop:8}}>or click to browse — scans with models in FILE/models</div></>)}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
            <div style={{textAlign:"center"}}>
              <AnimatePresence mode="wait">
                {phase==="scanning"?(
                  <motion.div key="scan" initial={{opacity:0,scale:.9}} animate={{opacity:1,scale:1}} exit={{opacity:0}}>
                    <div className="glass-card" style={{borderRadius:16,padding:"8px 56px",display:"inline-block",border:"1px solid rgba(0,229,255,.15)"}}><ScanAnim/></div>
                  </motion.div>
                ):(
                  <motion.div key="btn" initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}}>
                    <motion.button onClick={analyze} disabled={!canScan} whileHover={canScan?{scale:1.04,y:-2}:{}} whileTap={canScan?{scale:.96}:{}} style={{padding:"17px 68px",borderRadius:10,border:"none",cursor:canScan?"pointer":"not-allowed",background:canScan?"linear-gradient(135deg,rgba(0,229,255,.16),rgba(124,58,237,.22))":"rgba(255,255,255,.02)",boxShadow:canScan?"0 0 40px rgba(0,229,255,.22),0 0 80px rgba(0,229,255,.08),inset 0 1px 0 rgba(0,229,255,.15)":"none",borderWidth:1,borderStyle:"solid",borderColor:canScan?"rgba(0,229,255,.38)":"rgba(255,255,255,.04)",transition:"all .3s",position:"relative",overflow:"hidden"}}>
                      {canScan&&<div style={{position:"absolute",inset:0,background:"linear-gradient(90deg,transparent,rgba(0,229,255,.05),transparent)",animation:"data-scroll 3s linear infinite"}}/>}
                      <span className="f-orb" style={{fontSize:14,letterSpacing:4.2,color:canScan?"#00E5FF":"rgba(100,140,170,.2)",position:"relative",zIndex:1}}>⬡ {scanLabel}</span>
                    </motion.button>
                    {!canScan&&<p className="f-mono" style={{color:"rgba(100,140,170,.3)",fontSize:11,letterSpacing:2.1,marginTop:16}}>{topic==="url"?"ENTER A URL TO BEGIN SCAN":topic==="file"?"UPLOAD A FILE TO BEGIN SCAN":topic==="text"?"PASTE SUBJECT OR BODY TO BEGIN SCAN":"UPLOAD AN EMAIL FILE TO BEGIN SCAN"}</p>}
                    {error&&<p className="f-mono" style={{color:"#FF7A8C",fontSize:12,letterSpacing:.8,marginTop:16}}>{error}</p>}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.section>
        )}
      </AnimatePresence>

      {/* Results */}
      <AnimatePresence>
        {phase==="result"&&(
          <motion.section initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}}>
            <motion.div initial={{opacity:0,y:-10}} animate={{opacity:1,y:0}} transition={{delay:.1}} style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
              <div style={{display:"flex",alignItems:"center",gap:12}}><div style={{width:6,height:6,borderRadius:"50%",background:"#00FFA3",boxShadow:"0 0 8px #00FFA3",animation:"pulse-ring 1.5s ease-in-out infinite"}}/><span className="f-orb" style={{fontSize:11,color:"rgba(0,255,163,.68)",letterSpacing:3.2}}>ANALYSIS COMPLETE</span><span className="f-mono" style={{fontSize:11,color:"rgba(100,140,170,.38)",letterSpacing:1.1}}>· 0.34s</span></div>
              <button onClick={reset} className="f-mono" style={{background:"none",border:"1px solid rgba(0,229,255,.15)",borderRadius:7,color:"rgba(100,140,170,.58)",padding:"8px 16px",cursor:"pointer",fontSize:11,letterSpacing:1.6,transition:"all .2s"}} onMouseEnter={e=>{e.target.style.color="#00E5FF";e.target.style.borderColor="rgba(0,229,255,.4)";}} onMouseLeave={e=>{e.target.style.color="rgba(100,140,170,.5)";e.target.style.borderColor="rgba(0,229,255,.15)";}}>← NEW SCAN</button>
            </motion.div>
            <motion.div initial={{opacity:0,y:24}} animate={{opacity:1,y:0}} transition={{delay:.15}} className="glass-card" style={{padding:"28px 32px",marginBottom:14}}>
              <div style={{display:"flex",flexWrap:"wrap",gap:28,alignItems:"center",justifyContent:"space-between"}}>
                <Verdict v={result.verdict} labelOverride={verdictLabelOverride} subOverride={verdictSubOverride}/>
                <RiskGauge score={result.riskScore}/>
                <div style={{display:"flex",flexDirection:"column",gap:20,flex:1,minWidth:200}}>
                  <BarStat label="DETECTION CONFIDENCE" val={result.confidence} color="#00E5FF" delay={.3}/>
                  <BarStat label={result.analysisType==="email"?"SPAM PROBABILITY":"MALICIOUS MODEL VOTES"} val={result.spamProb} color="#FF4D6D" delay={.4}/>
                  <BarStat label={result.analysisType==="email"?"PHISHING LANGUAGE SCORE":"RISK SCORE"} val={result.analysisType==="email"?phishScore:result.riskScore} color="#FFD60A" delay={.5}/>
                </div>
              </div>
            </motion.div>
            {result.analysisType==="email"?(
              <>
                {result.inputSource==="manual_text" && (
                  <motion.div initial={{opacity:0,y:18}} animate={{opacity:1,y:0}} transition={{delay:.22}} className="glass-card" style={{padding:"16px 20px",marginBottom:14,border:"1px solid rgba(255,214,10,.18)",background:"linear-gradient(135deg,rgba(255,214,10,.05),rgba(6,12,24,.85))"}}>
                    <div className="f-mono" style={{fontSize:12,color:"rgba(255,214,10,.82)",letterSpacing:1.5,marginBottom:6}}>MANUAL TEXT MODE</div>
                    <div className="f-mono" style={{fontSize:12,color:"rgba(200,220,238,.72)",lineHeight:1.75}}>This result was generated from pasted subject/body text. Header authentication signals such as SPF, DKIM, and DMARC were not fully available.</div>
                  </motion.div>
                )}
                <motion.div initial={{opacity:0,y:18}} animate={{opacity:1,y:0}} transition={{delay:.25}} className="glass-card" style={{padding:"22px 26px",marginBottom:14}}>
                  <div className="f-orb" style={{fontSize:11,color:"rgba(100,140,170,.52)",letterSpacing:3.2,marginBottom:16}}>ACTIVE THREAT INDICATORS</div>
                  {result.threats.length ? (
                    <div style={{display:"flex",flexWrap:"wrap",gap:8}}>
                      {result.threats.map((t,i)=>(<Tag key={t} label={t.toUpperCase()} color={["#FF4D6D","#FFD60A","#FF4D6D","#FFD60A","#7C3AED","#FF4D6D","#FF4D6D","#FFD60A"][i]} delay={.35+i*.05}/>))}
                    </div>
                  ) : (
                    <div className="f-mono" style={{fontSize:13,color:"rgba(120,150,175,.62)"}}>No elevated threat indicators were returned for this email.</div>
                  )}
                </motion.div>
                <motion.div initial={{opacity:0,y:18}} animate={{opacity:1,y:0}} transition={{delay:.35}} style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(150px,1fr))",gap:12,marginBottom:14}}>
                  <StatCard icon="🔗" label="EXTRACTED LINKS" value={result.stats.links} color="#00E5FF" delay={.4}/>
                  <StatCard icon="📄" label="HTML CONTENT" value={result.stats.html?"YES":"NO"} color="#7C3AED" raw delay={.45}/>
                  <StatCard icon="📎" label="ATTACHMENTS" value={result.stats.attach} color="#FF4D6D" delay={.5}/>
                  <StatCard icon="⚠️" label="PHISH KEYWORDS" value={result.stats.phishKw} color="#FFD60A" delay={.55}/>
                </motion.div>
                <motion.div initial={{opacity:0}} animate={{opacity:1}} transition={{delay:.45}}>
                  <div className="f-orb" style={{fontSize:11,color:"rgba(100,140,170,.52)",letterSpacing:3.2,marginBottom:14}}>FORENSIC ANALYSIS</div>
                  <Panel title="HEADER ANALYSIS" icon="🔍" color="#00E5FF" delay={.5} defaultOpen={true}>
                    <div style={{marginTop:10}}>
                      <DRow k="FROM" v={result.headers.from} status={result.headers.from==="N/A"?"na":"pass"}/>
                      <DRow k="REPLY-TO" v={result.headers.replyTo} status={replyToStatus}/>
                      <DRow k="RETURN-PATH" v={result.headers.returnPath} status={result.headers.returnPath==="N/A"?"na":"pass"}/>
                      <DRow k="SPF" v={result.headers.spf} status={authStatusToRowStatus(result.headers.spfStatus)}/>
                      <DRow k="DKIM" v={result.headers.dkim} status={authStatusToRowStatus(result.headers.dkimStatus)}/>
                      <DRow k="DMARC" v={result.headers.dmarc} status={authStatusToRowStatus(result.headers.dmarcStatus)}/>
                      <DRow k="DOMAIN ALIGNMENT" v={result.headers.domain} status={headerDomainStatus}/>
                      {Array.isArray(result.headers.warnings) && result.headers.warnings.length>0 && (
                        <div style={{marginTop:12,padding:"10px 12px",borderRadius:8,background:"rgba(255,214,10,.05)",border:"1px solid rgba(255,214,10,.2)"}}>
                          <div className="f-mono" style={{fontSize:11,color:"rgba(255,214,10,.78)",letterSpacing:1.6,marginBottom:8}}>HEADER WARNINGS</div>
                          <div style={{display:"flex",flexDirection:"column",gap:6}}>
                            {result.headers.warnings.slice(0,4).map((w)=><span key={w} className="f-mono" style={{fontSize:12,color:"rgba(255,214,10,.82)",lineHeight:1.7}}>{w}</span>)}
                          </div>
                        </div>
                      )}
                    </div>
                  </Panel>
                  <Panel title="URL ANALYSIS" icon="🌐" color="#00FFA3" delay={.55}>
                    <div style={{marginTop:10,display:"flex",flexDirection:"column",gap:8}}>
                      {result.urls.length===0 && (
                        <div className="f-mono" style={{fontSize:13,color:"rgba(120,150,175,.62)"}}>No URLs extracted from this email.</div>
                      )}
                      {result.urls.map(({url,domain,type,tone},i)=>{
                        const palette=tone==="bad"
                          ? {text:"#FF4D6D",bg:"rgba(255,77,109,.04)",border:"rgba(255,77,109,.15)",badgeBg:"rgba(255,77,109,.08)",badgeBorder:"rgba(255,77,109,.25)"}
                          : tone==="warn"
                            ? {text:"#FFD60A",bg:"rgba(255,214,10,.04)",border:"rgba(255,214,10,.2)",badgeBg:"rgba(255,214,10,.08)",badgeBorder:"rgba(255,214,10,.25)"}
                            : tone==="pass"
                              ? {text:"#00FFA3",bg:"rgba(0,255,163,.03)",border:"rgba(0,255,163,.12)",badgeBg:"rgba(0,255,163,.06)",badgeBorder:"rgba(0,255,163,.18)"}
                              : {text:"#8A7AAE",bg:"rgba(138,122,174,.05)",border:"rgba(138,122,174,.2)",badgeBg:"rgba(138,122,174,.08)",badgeBorder:"rgba(138,122,174,.3)"};
                        return (
                          <div key={`${url}-${i}`} style={{display:"flex",alignItems:"center",gap:10,padding:"10px 14px",borderRadius:8,background:palette.bg,border:`1px solid ${palette.border}`}}>
                            <span className="f-mono" style={{fontSize:11,color:palette.text,letterSpacing:1.2}}>{tone==="bad"?"RISK":tone==="warn"?"WARN":tone==="pass"?"OK":"N/A"}</span>
                            <div style={{display:"flex",flexDirection:"column",gap:4,flex:1,minWidth:0}}>
                              <span className="f-mono" style={{fontSize:12,color:palette.text,wordBreak:"break-all",lineHeight:1.7}}>{url}</span>
                              <span className="f-mono" style={{fontSize:11,color:"rgba(130,160,185,.62)"}}>Domain: {domain}</span>
                            </div>
                            <span className="f-mono" style={{fontSize:10,color:palette.text,background:palette.badgeBg,border:`1px solid ${palette.badgeBorder}`,padding:"4px 9px",borderRadius:4,flexShrink:0}}>{type}</span>
                          </div>
                        );
                      })}
                    </div>
                  </Panel>
                  <Panel title="ATTACHMENT ANALYSIS" icon="📎" color="#FF4D6D" delay={.6}>
                    <div style={{marginTop:10,display:"flex",flexDirection:"column",gap:8}}>
                      {result.attach.length===0 && (
                        <div style={{padding:"12px 14px",borderRadius:8,background:"rgba(0,255,163,.03)",border:"1px solid rgba(0,255,163,.16)"}}>
                          <div className="f-mono" style={{fontSize:13,color:"#00FFA3"}}>No attachments detected.</div>
                        </div>
                      )}
                      {result.attach.map((a,i)=>{
                        const bad=Boolean(a.danger);
                        return (
                          <div key={`${a.name}-${i}`} style={{display:"flex",alignItems:"center",gap:12,padding:"12px 14px",borderRadius:8,background:bad?"rgba(255,77,109,.04)":"rgba(0,255,163,.03)",border:`1px solid ${bad?"rgba(255,77,109,.16)":"rgba(0,255,163,.18)"}`}}>
                            <span className="f-mono" style={{fontSize:11,color:bad?"#FF4D6D":"#00FFA3",letterSpacing:1.1}}>{bad?"RISK":"OK"}</span>
                            <div style={{flex:1}}>
                              <div className="f-mono" style={{fontSize:13,color:bad?"#FF4D6D":"#00FFA3"}}>{a.name}</div>
                              <div className="f-mono" style={{fontSize:11,color:bad?"rgba(255,77,109,.62)":"rgba(0,255,163,.62)",marginTop:3,lineHeight:1.6}}>{a.reason}</div>
                            </div>
                            <span className="f-mono" style={{fontSize:10,color:bad?"#FF4D6D":"#00FFA3",background:bad?"rgba(255,77,109,.1)":"rgba(0,255,163,.08)",border:`1px solid ${bad?"rgba(255,77,109,.3)":"rgba(0,255,163,.3)"}`,padding:"4px 10px",borderRadius:4}}>
                              {(a.ext||"n/a").toUpperCase()}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </Panel>
                  <Panel title="LANGUAGE SIGNALS" icon="🧠" color="#7C3AED" delay={.65}>
                    <div style={{marginTop:14}}>
                      <div className="f-mono" style={{fontSize:11,color:"rgba(100,140,170,.5)",letterSpacing:2.1,marginBottom:10}}>DETECTED SIGNALS</div>
                      {result.kw.length===0 ? (
                        <div className="f-mono" style={{fontSize:13,color:"rgba(120,150,175,.62)"}}>No elevated language-risk indicators were returned.</div>
                      ) : (
                        <div style={{display:"flex",flexWrap:"wrap",gap:8}}>
                          {result.kw.map((kw)=>(<span key={kw} className="f-mono" style={{fontSize:12,color:"#9B6FE0",background:"rgba(124,58,237,.08)",border:"1px solid rgba(124,58,237,.22)",padding:"6px 13px",borderRadius:6}}>{kw}</span>))}
                        </div>
                      )}
                      <div style={{marginTop:18,padding:"14px 16px",borderRadius:8,background:"rgba(124,58,237,.05)",border:"1px solid rgba(124,58,237,.14)"}}>
                        <BarStat label="LANGUAGE RISK (HEURISTIC)" val={languageRisk} color="#7C3AED"/>
                        <BarStat label="PHISHING LANGUAGE (HEURISTIC)" val={phishScore} color="#9B6FE0"/>
                        <div className="f-mono" style={{fontSize:11,color:"rgba(124,58,237,.6)",marginTop:10,lineHeight:1.7}}>Scores are derived from backend heuristic language rules.</div>
                      </div>
                    </div>
                  </Panel>
                </motion.div>
              </>
            ):(
              <>
                <motion.div initial={{opacity:0,y:18}} animate={{opacity:1,y:0}} transition={{delay:.25}} className="glass-card" style={{padding:"22px 26px",marginBottom:14}}>
                  <div className="f-orb" style={{fontSize:11,color:"rgba(100,140,170,.52)",letterSpacing:3.2,marginBottom:12}}>{result.detailTitle}</div>
                  <div className="f-mono" style={{fontSize:14,color:"rgba(200,220,238,.82)",marginBottom:10,wordBreak:"break-all",lineHeight:1.75}}>{result.target || "N/A"}</div>
                  {result.threats.length ? (
                    <div style={{display:"flex",flexWrap:"wrap",gap:8}}>
                      {result.threats.map((t,i)=>(<Tag key={t} label={t.toUpperCase()} color={["#FF4D6D","#FFD60A","#00E5FF","#7C3AED","#00FFA3","#FF4D6D"][i % 6]}/>))}
                    </div>
                  ) : (
                    <div className="f-mono" style={{fontSize:13,color:"rgba(120,150,175,.62)"}}>No additional summary was returned by the backend.</div>
                  )}
                </motion.div>
                <motion.div initial={{opacity:0,y:18}} animate={{opacity:1,y:0}} transition={{delay:.35}} style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(150px,1fr))",gap:12,marginBottom:14}}>
                  <StatCard icon="🧠" label="MODELS" value={result.modelResults.length} color="#00E5FF" raw delay={.4}/>
                  <StatCard icon="⚠️" label="MALICIOUS VOTES" value={`${result.spamProb}%`} color="#FF4D6D" raw delay={.45}/>
                  <StatCard icon={result.analysisType==="url"?"🌐":"📁"} label="TARGET TYPE" value={result.analysisType.toUpperCase()} color="#7C3AED" raw delay={.5}/>
                  <StatCard icon="🗂️" label="FEATURES" value={Object.keys(result.features || {}).length} color="#FFD60A" raw delay={.55}/>
                </motion.div>
                <motion.div initial={{opacity:0}} animate={{opacity:1}} transition={{delay:.45}}>
                  <div className="f-orb" style={{fontSize:11,color:"rgba(100,140,170,.52)",letterSpacing:3.2,marginBottom:14}}>MODEL ANALYSIS</div>
                  <Panel title="MODEL RESULTS" icon="🧪" color="#00E5FF" delay={.5} defaultOpen={true}>
                    <div style={{marginTop:10,display:"flex",flexDirection:"column",gap:8}}>
                      {result.modelResults.map((item)=>(
                        <div key={item.model} style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:12,padding:"12px 14px",borderRadius:8,background:item.isMalicious?"rgba(255,77,109,.04)":"rgba(0,255,163,.03)",border:`1px solid ${item.isMalicious?"rgba(255,77,109,.16)":"rgba(0,255,163,.18)"}`}}>
                          <div style={{display:"flex",flexDirection:"column",gap:4}}>
                            <span className="f-mono" style={{fontSize:13,color:item.isMalicious?"#FF4D6D":"#00FFA3",letterSpacing:1.3}}>{item.model.toUpperCase()}</span>
                            <span className="f-mono" style={{fontSize:11,color:"rgba(130,160,185,.62)"}}>{item.prediction}</span>
                          </div>
                          <span className="f-mono" style={{fontSize:12,color:item.isMalicious?"#FF4D6D":"#00FFA3"}}>{item.confidence==null?"N/A":`${item.confidence}%`}</span>
                        </div>
                      ))}
                    </div>
                  </Panel>
                  <Panel title="FEATURE SNAPSHOT" icon={result.analysisType==="url"?"🌐":"📎"} color="#00FFA3" delay={.55} defaultOpen={true}>
                    <div style={{marginTop:10}}>
                      {Object.entries(result.features || {}).slice(0, 12).map(([key,value])=>(
                        <div key={key} style={{display:"flex",gap:10,alignItems:"center",padding:"8px 0",borderBottom:"1px solid rgba(0,229,255,.05)"}}>
                          <span className="f-mono" style={{fontSize:11,color:"rgba(100,140,170,.58)",letterSpacing:1.3,minWidth:160}}>{humanizeFeatureKey(key)}</span>
                          <span className="f-mono" style={{fontSize:12,color:"#00FFA3",flex:1,wordBreak:"break-word",lineHeight:1.7}}>{formatFeatureValue(value)}</span>
                        </div>
                      ))}
                    </div>
                  </Panel>
                  <Panel title="WHY THIS SCORE" icon="📊" color="#7C3AED" delay={.58} defaultOpen={true}>
                    <div style={{marginTop:10,display:"flex",flexDirection:"column",gap:12}}>
                      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(170px,1fr))",gap:10}}>
                        <div style={{padding:"12px 14px",borderRadius:8,background:"rgba(124,58,237,.05)",border:"1px solid rgba(124,58,237,.16)"}}>
                          <div className="f-mono" style={{fontSize:11,color:"rgba(140,115,210,.75)",letterSpacing:1.4}}>MODEL VOTES</div>
                          <div className="f-orb" style={{fontSize:22,color:"#C8DCEE",marginTop:8}}>{result.scoreBreakdown.harmfulVotes}/{result.scoreBreakdown.totalModels}</div>
                          <div className="f-mono" style={{fontSize:11,color:"rgba(180,205,225,.62)",marginTop:6,lineHeight:1.6}}>{formatPercentLabel(result.scoreBreakdown.harmfulVotePercent)} of models flagged this asset.</div>
                        </div>
                        <div style={{padding:"12px 14px",borderRadius:8,background:"rgba(0,229,255,.04)",border:"1px solid rgba(0,229,255,.14)"}}>
                          <div className="f-mono" style={{fontSize:11,color:"rgba(0,229,255,.72)",letterSpacing:1.4}}>MALICIOUS CONFIDENCE</div>
                          <div className="f-orb" style={{fontSize:22,color:"#C8DCEE",marginTop:8}}>{formatPercentLabel(result.scoreBreakdown.confidencePercent)}</div>
                          <div className="f-mono" style={{fontSize:11,color:"rgba(180,205,225,.62)",marginTop:6,lineHeight:1.6}}>Average harmful-class probability used by the ensemble.</div>
                        </div>
                        <div style={{padding:"12px 14px",borderRadius:8,background:"rgba(255,214,10,.04)",border:"1px solid rgba(255,214,10,.16)"}}>
                          <div className="f-mono" style={{fontSize:11,color:"rgba(255,214,10,.78)",letterSpacing:1.4}}>FINAL RISK</div>
                          <div className="f-orb" style={{fontSize:22,color:"#C8DCEE",marginTop:8}}>{formatPercentLabel(result.scoreBreakdown.riskAfterAdjustment)}</div>
                          <div className="f-mono" style={{fontSize:11,color:"rgba(180,205,225,.62)",marginTop:6,lineHeight:1.6}}>Weighted from votes and malicious confidence.</div>
                        </div>
                      </div>
                      <div style={{padding:"14px 16px",borderRadius:8,background:"rgba(6,12,24,.72)",border:"1px solid rgba(124,58,237,.18)"}}>
                        <div className="f-mono" style={{fontSize:11,color:"rgba(140,115,210,.78)",letterSpacing:1.4,marginBottom:10}}>ENSEMBLE FORMULA</div>
                        <div className="f-mono" style={{fontSize:12,color:"rgba(200,220,238,.76)",lineHeight:1.75}}>
                          {`Votes (${result.scoreBreakdown.voteWeightPercent}% weight): ${formatPercentLabel(result.scoreBreakdown.harmfulVotePercent, 2)} contributes ${formatPercentLabel(result.scoreBreakdown.voteComponentPercent, 2)}.`}
                        </div>
                        <div className="f-mono" style={{fontSize:12,color:"rgba(200,220,238,.76)",lineHeight:1.75}}>
                          {`Confidence (${result.scoreBreakdown.confidenceWeightPercent}% weight): ${formatPercentLabel(result.scoreBreakdown.confidencePercent, 2)} contributes ${formatPercentLabel(result.scoreBreakdown.confidenceComponentPercent, 2)}.`}
                        </div>
                        <div className="f-mono" style={{fontSize:12,color:"rgba(200,220,238,.76)",lineHeight:1.75}}>
                          {`Base risk: ${formatPercentLabel(result.scoreBreakdown.riskBeforeAdjustment, 2)}. Final risk: ${formatPercentLabel(result.scoreBreakdown.riskAfterAdjustment, 2)}.`}
                        </div>
                        {result.scoreBreakdown.trustAdjustmentFactor < 1 ? (
                          <div className="f-mono" style={{fontSize:12,color:"rgba(0,229,255,.78)",lineHeight:1.75}}>
                            {`Trusted-domain adjustment applied with factor ${result.scoreBreakdown.trustAdjustmentFactor.toFixed(2)}.`}
                          </div>
                        ) : (
                          <div className="f-mono" style={{fontSize:12,color:"rgba(120,150,175,.62)",lineHeight:1.75}}>
                            No trust adjustment was applied to this score.
                          </div>
                        )}
                      </div>
                    </div>
                  </Panel>
                  <Panel title="ANALYST SUMMARY" icon="🧾" color="#FFD60A" delay={.6} defaultOpen={true}>
                    <div style={{marginTop:10,display:"flex",flexDirection:"column",gap:10}}>
                      <div className="f-mono" style={{fontSize:12,color:"rgba(255,214,10,.82)",wordBreak:"break-all"}}>Classification: {result.classificationLabel}</div>
                      {result.sourceDir && <div className="f-mono" style={{fontSize:11,color:"rgba(130,160,185,.6)",wordBreak:"break-all",lineHeight:1.7}}>Source: {result.sourceDir}</div>}
                      {result.summary.length ? result.summary.map((item)=>(
                        <div key={item} className="f-mono" style={{fontSize:12,color:"rgba(200,220,238,.78)",lineHeight:1.75}}>{item}</div>
                      )) : <div className="f-mono" style={{fontSize:12,color:"rgba(120,150,175,.62)"}}>No summary details available.</div>}
                    </div>
                  </Panel>
                </motion.div>
              </>
            )}
          </motion.section>
        )}
      </AnimatePresence>

      <motion.footer initial={{opacity:0}} animate={{opacity:1}} transition={{delay:1.2}} style={{textAlign:"center",marginTop:72,paddingTop:30,borderTop:"1px solid rgba(0,229,255,.05)"}}>
        <div style={{display:"flex",justifyContent:"center",alignItems:"center",gap:20,flexWrap:"wrap"}}>{["247,832 THREATS TRACKED","99.98% UPTIME","<15ms LATENCY","AI MODEL v2.4.1"].map(s=>(<span key={s} className="f-mono" style={{fontSize:11,color:"rgba(100,140,170,.28)",letterSpacing:1.2}}>{s}</span>))}</div>
        <div className="f-mono" style={{fontSize:10,color:"rgba(100,140,170,.18)",marginTop:12,letterSpacing:3}}>SENTINEL AI · THREAT INTELLIGENCE PLATFORM · BUILD 2026.03</div>
      </motion.footer>
    </div>
  );
};

/* ═══════════════════════════════════════════════════════════════
   ROOT APP
═══════════════════════════════════════════════════════════════ */
export default function App() {
  const [page, setPage] = useState("landing");
  const [scrollY, setScrollY] = useState(0);
  const mx = useMotionValue(600), my = useMotionValue(400);
  

  useEffect(()=>{
    const onScroll=()=>setScrollY(window.scrollY);
    const onMove=e=>{mx.set(e.clientX);my.set(e.clientY);};
    window.addEventListener("scroll",onScroll);
    window.addEventListener("mousemove",onMove);
    return()=>{window.removeEventListener("scroll",onScroll);window.removeEventListener("mousemove",onMove);};
  },[]);

  const goToPage = (nextPage) => { setPage(nextPage); window.scrollTo({top:0,behavior:"smooth"}); };
  const goHome  = () => { setPage("landing"); window.scrollTo({top:0,behavior:"smooth"}); };

  return (
    <div style={{minHeight:"100vh",position:"relative"}}>
      <GlobalStyles/>
      <AuroraBlobs/>
      <Nav page={page} setPage={p=>{if(p==="landing")goHome();else goToPage(p);}} scrollY={scrollY}/>
      <AnimatePresence mode="wait">
        {page==="landing" ? (
          <motion.div key="landing" initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0,x:-40}} transition={{duration:.4}}>
            <LandingPage mx={mx} my={my} setPage={goToPage}/>
          </motion.div>
        ) : page==="dashboard" ? (
          <motion.div key="dashboard" initial={{opacity:0,x:40}} animate={{opacity:1,x:0}} exit={{opacity:0,x:40}} transition={{duration:.4}}>
            <DashboardPage />
          </motion.div>
        ) : (
          <motion.div key={page} initial={{opacity:0,x:40}} animate={{opacity:1,x:0}} exit={{opacity:0,x:40}} transition={{duration:.4}}>
            <AnalyzerApp topic={page}/>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
