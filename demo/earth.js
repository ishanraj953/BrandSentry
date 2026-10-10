/*
 * BrandSentra - 3D Interactive Animated Earth Globe
 * Inspired by BrandSentra Intaglio Design System
 */
(function () {
  "use strict";

  const R = 1.6;
  const LAVENDER = 0xb6a4ff;
  const YELLOW = 0xf2cb55;
  const CORAL = 0xff7a72;
  const COBALT = 0x6e56cf;

  const GLOBE_NODES = [
    { id: 'n1', lat: 19, lon: 73, kind: 'official', category: 'Official website', label: 'Registered domain', detail: 'The reference every link is checked against. Subdomains inherit trust.' },
    { id: 'n2', lat: 51, lon: 0, kind: 'official', category: 'Social profile', label: 'Verified social account', detail: 'Registered handles are excluded before any scoring takes place.' },
    { id: 'n3', lat: 40, lon: -74, kind: 'official', category: 'Company page', label: 'LinkedIn company page', detail: 'Professional pages are a common target for fake recruitment.' },
    { id: 'n4', lat: 1, lon: 104, kind: 'official', category: 'Mobile app', label: 'Official app listing', detail: 'Package identifier and publisher form the app baseline.' },
    { id: 'n5', lat: -33, lon: 151, kind: 'official', category: 'Support channel', label: 'Authorized support', detail: 'Outsourced or regional support accounts stay excluded but reviewable.' },
    { id: 'n6', lat: 35, lon: 139, kind: 'candidate', category: 'Look-alike profile', label: 'Similar name detected', detail: 'Name resembles the brand. Needs corroboration before it is prioritized.' },
    { id: 'n7', lat: -23, lon: -46, kind: 'candidate', category: 'Look-alike app', label: 'Publisher differs', detail: 'A different publisher is a signal to investigate, not proof.' },
    { id: 'n8', lat: 25, lon: 55, kind: 'flagged', category: 'Suspicious destination', label: 'Unregistered link', detail: 'Several candidates point to the same unregistered host.' },
    { id: 'n9', lat: 48, lon: 11, kind: 'candidate', category: 'Fake company page', label: 'Spacing variation', detail: 'Brand split with a space plus an added word such as “refunds”.' },
    { id: 'n10', lat: 37, lon: -122, kind: 'flagged', category: 'Scam account', label: 'Claims official status', detail: 'Asks for payments over DM while claiming to be support.' },
    { id: 'n11', lat: -1, lon: 37, kind: 'candidate', category: 'Unregistered channel', label: 'Missing registration', detail: 'A platform where the brand has no registered account yet.' },
    { id: 'n12', lat: 60, lon: -100, kind: 'official', category: 'Regional account', label: 'Regional identity', detail: 'Regional accounts must be registered so they are never confused with copies.' }
  ];

  const GLOBE_ARCS = [
    ['n6', 'n2'], ['n7', 'n4'], ['n8', 'n10'], ['n9', 'n3'], ['n8', 'n6'], ['n11', 'n5'], ['n10', 'n1'], ['n12', 'n2']
  ];

  const DEMO_STEPS = [
    { title: 'Register the baseline', body: 'Official website, social accounts, company pages, apps and support channels light up as the trusted reference.' },
    { title: 'Analyze candidates', body: 'External assets that resemble the brand are collected from the sources connected for this organization.' },
    { title: 'Assess relationships', body: 'Each candidate is compared with the registry. Shared destinations and publisher differences are drawn as relationships.' },
    { title: 'Protect and respond', body: 'The perimeter tightens around what is official. Findings move into investigation with evidence attached.' }
  ];

  function toVec(lat, lon, r) {
    const phi = ((90 - lat) * Math.PI) / 180;
    const theta = ((lon + 180) * Math.PI) / 180;
    return new THREE.Vector3(-r * Math.sin(phi) * Math.cos(theta), r * Math.cos(phi), r * Math.sin(phi) * Math.sin(theta));
  }

  function hasWebGL() {
    try {
      const c = document.createElement('canvas');
      return !!(c.getContext('webgl2') || c.getContext('webgl'));
    } catch (e) {
      return false;
    }
  }

  const NOISE_GLSL = `
vec3 mod289(vec3 x){return x-floor(x*(1.0/289.0))*289.0;}
vec4 mod289(vec4 x){return x-floor(x*(1.0/289.0))*289.0;}
vec4 permute(vec4 x){return mod289(((x*34.0)+1.0)*x);}
vec4 taylorInvSqrt(vec4 r){return 1.79284291400159-0.85373472095314*r;}
float snoise(vec3 v){
  const vec2 C=vec2(1.0/6.0,1.0/3.0); const vec4 D=vec4(0.0,0.5,1.0,2.0);
  vec3 i=floor(v+dot(v,C.yyy)); vec3 x0=v-i+dot(i,C.xxx);
  vec3 g=step(x0.yzx,x0.xyz); vec3 l=1.0-g; vec3 i1=min(g.xyz,l.zxy); vec3 i2=max(g.xyz,l.zxy);
  vec3 x1=x0-i1+C.xxx; vec3 x2=x0-i2+C.yyy; vec3 x3=x0-D.yyy;
  i=mod289(i);
  vec4 p=permute(permute(permute(i.z+vec4(0.0,i1.z,i2.z,1.0))+i.y+vec4(0.0,i1.y,i2.y,1.0))+i.x+vec4(0.0,i1.x,i2.x,1.0));
  float n_=0.142857142857; vec3 ns=n_*D.wyz-D.xzx;
  vec4 j=p-49.0*floor(p*ns.z*ns.z); vec4 x_=floor(j*ns.z); vec4 y_=floor(j-7.0*x_);
  vec4 x=x_*ns.x+ns.yyyy; vec4 y=y_*ns.x+ns.yyyy; vec4 h=1.0-abs(x)-abs(y);
  vec4 b0=vec4(x.xy,y.xy); vec4 b1=vec4(x.zw,y.zw);
  vec4 s0=floor(b0)*2.0+1.0; vec4 s1=floor(b1)*2.0+1.0; vec4 sh=-step(h,vec4(0.0));
  vec4 a0=b0.xzyw+s0.xzyw*sh.xxyy; vec4 a1=b1.xzyw+s1.xzyw*sh.zzww;
  vec3 p0=vec3(a0.xy,h.x); vec3 p1=vec3(a0.zw,h.y); vec3 p2=vec3(a1.xy,h.z); vec3 p3=vec3(a1.zw,h.w);
  vec4 norm=taylorInvSqrt(vec4(dot(p0,p0),dot(p1,p1),dot(p2,p2),dot(p3,p3)));
  p0*=norm.x; p1*=norm.y; p2*=norm.z; p3*=norm.w;
  vec4 m=max(0.6-vec4(dot(x0,x0),dot(x1,x1),dot(x2,x2),dot(x3,x3)),0.0); m=m*m;
  return 42.0*dot(m*m,vec4(dot(p0,x0),dot(p1,x1),dot(p2,x2),dot(p3,x3)));
}
float fbm(vec3 p){ float a=0.5; float s=0.0; for(int i=0;i<4;i++){ s+=a*snoise(p); p*=2.03; a*=0.5; } return s; }
`;

  const earthVert = `
varying vec3 vObj; varying vec3 vNormalW; varying vec3 vViewDir;
void main(){
  vObj = normalize(position);
  vec4 wp = modelMatrix * vec4(position,1.0);
  vNormalW = normalize(mat3(modelMatrix) * normal);
  vViewDir = normalize(cameraPosition - wp.xyz);
  gl_Position = projectionMatrix * viewMatrix * wp;
}`;

  const earthFrag = `
uniform float uIntro; uniform vec3 uLav; uniform vec3 uYel;
varying vec3 vObj; varying vec3 vNormalW; varying vec3 vViewDir;
${NOISE_GLSL}
const float PI = 3.14159265;
void main(){
  float lat = asin(clamp(vObj.y,-1.0,1.0));
  float lon = atan(vObj.z, vObj.x);
  float n = fbm(vObj * 1.55 + vec3(3.1, 1.7, 0.4));
  float land = smoothstep(0.02, 0.09, n);
  float rows = 110.0;
  float latC = (lat + PI*0.5) / PI * rows;
  float row = floor(latC);
  float rowLat = (row + 0.5) / rows * PI - PI*0.5;
  float cols = max(6.0, floor(rows * 2.0 * cos(rowLat)));
  float lonC = (lon + PI) / (2.0*PI) * cols;
  vec2 cell = vec2(fract(lonC), fract(latC)) - 0.5;
  float dotMask = 1.0 - smoothstep(0.18, 0.32, length(cell));
  float gLat = abs(fract(lat / (PI/12.0)) - 0.5);
  float gLon = abs(fract(lon / (PI/12.0)) - 0.5);
  float grid = (1.0 - smoothstep(0.0, 0.012, 0.5 - max(gLat, gLon)));
  vec3 ocean = vec3(0.075, 0.05, 0.13);
  vec3 col = ocean + vec3(0.03,0.02,0.06) * (1.0 - abs(vObj.y));
  col = mix(col, uLav * 0.75, land * dotMask * 0.85);
  col += uLav * 0.06 * land;
  col += uLav * 0.05 * grid;
  vec3 L = normalize(vec3(-0.6, 0.5, 0.9));
  float diff = clamp(dot(vNormalW, L) * 0.6 + 0.5, 0.25, 1.0);
  col *= diff;
  float fres = pow(1.0 - clamp(dot(vNormalW, vViewDir), 0.0, 1.0), 2.6);
  col += uLav * fres * 0.9 + uYel * pow(fres, 6.0) * 0.25;
  gl_FragColor = vec4(col, uIntro);
}`;

  const atmoVert = `
varying vec3 vN; varying vec3 vV;
void main(){ vec4 wp = modelMatrix*vec4(position,1.0); vN = normalize(mat3(modelMatrix)*normal); vV = normalize(cameraPosition - wp.xyz); gl_Position = projectionMatrix*viewMatrix*wp; }`;

  const atmoFrag = `
uniform vec3 uColor; uniform float uAlpha; varying vec3 vN; varying vec3 vV;
void main(){ float i = pow(0.62 - dot(vN, vV), 3.2); gl_FragColor = vec4(uColor, 1.0) * i * uAlpha; }`;

  function initEarth(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!window.THREE || !hasWebGL()) {
      renderFallback(container);
      return;
    }

    const w = container.clientWidth || 540;
    const h = container.clientHeight || 540;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(38, w / h, 0.1, 100);
    camera.position.set(0, 0, 5.2);

    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: "high-performance" });
    renderer.setSize(w, h);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    container.innerHTML = "";
    container.appendChild(renderer.domElement);

    const rootGroup = new THREE.Group();
    scene.add(rootGroup);

    // Globe
    const globeMat = new THREE.ShaderMaterial({
      vertexShader: earthVert,
      fragmentShader: earthFrag,
      transparent: true,
      uniforms: {
        uIntro: { value: 1.0 },
        uLav: { value: new THREE.Color(LAVENDER) },
        uYel: { value: new THREE.Color(YELLOW) }
      }
    });
    const globeMesh = new THREE.Mesh(new THREE.SphereGeometry(R, 80, 80), globeMat);
    rootGroup.add(globeMesh);

    // Atmosphere
    const atmoMat = new THREE.ShaderMaterial({
      vertexShader: atmoVert,
      fragmentShader: atmoFrag,
      side: THREE.BackSide,
      blending: THREE.AdditiveBlending,
      transparent: true,
      depthWrite: false,
      uniforms: {
        uColor: { value: new THREE.Color(0x9a83e8) },
        uAlpha: { value: 0.65 }
      }
    });
    const atmoMesh = new THREE.Mesh(new THREE.SphereGeometry(R * 1.13, 60, 60), atmoMat);
    rootGroup.add(atmoMesh);

    // Nodes
    const nodeMeshes = [];
    const nodeGroup = new THREE.Group();
    rootGroup.add(nodeGroup);

    GLOBE_NODES.forEach((n) => {
      const pos = toVec(n.lat, n.lon, R * 1.01);
      const out = pos.clone().normalize();
      const quat = new THREE.Quaternion().setFromUnitVectors(new THREE.Vector3(0, 0, 1), out);
      const grp = new THREE.Group();
      grp.position.copy(pos);
      grp.quaternion.copy(quat);

      const col = n.kind === 'official' ? LAVENDER : n.kind === 'flagged' ? CORAL : YELLOW;
      const core = new THREE.Mesh(new THREE.SphereGeometry(0.04, 16, 16), new THREE.MeshBasicMaterial({ color: col }));
      const halo = new THREE.Mesh(new THREE.RingGeometry(0.045, 0.065, 32), new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.4, side: THREE.DoubleSide, depthWrite: false }));

      grp.add(core);
      grp.add(halo);
      grp.userData = { node: n, core, halo };
      nodeMeshes.push(grp);
      nodeGroup.add(grp);
    });

    // Connection Arcs
    const arcGroup = new THREE.Group();
    rootGroup.add(arcGroup);
    const SEG = 48;
    const arcsData = GLOBE_ARCS.map(([aId, bId], idx) => {
      const A = GLOBE_NODES.find(n => n.id === aId);
      const B = GLOBE_NODES.find(n => n.id === bId);
      if (!A || !B) return null;
      const va = toVec(A.lat, A.lon, R * 1.01);
      const vb = toVec(B.lat, B.lon, R * 1.01);
      const mid = va.clone().add(vb).multiplyScalar(0.5);
      const h = R * (1.18 + va.distanceTo(vb) * 0.16);
      const curve = new THREE.QuadraticBezierCurve3(va, mid.normalize().multiplyScalar(h), vb);
      const geo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(SEG));
      const isFlagged = A.kind === 'flagged' || B.kind === 'flagged';
      const color = isFlagged ? CORAL : idx % 3 === 0 ? YELLOW : LAVENDER;
      const mat = new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.55 });
      const line = new THREE.Line(geo, mat);
      const dot = new THREE.Mesh(new THREE.SphereGeometry(0.02, 8, 8), new THREE.MeshBasicMaterial({ color }));
      arcGroup.add(line);
      arcGroup.add(dot);
      return { curve, geo, mat, dot, offset: idx * 1.4 };
    }).filter(Boolean);

    // Geodesic Shield
    const ico = new THREE.IcosahedronGeometry(R * 1.34, 1);
    const edges = new THREE.EdgesGeometry(ico);
    const shieldMat = new THREE.LineBasicMaterial({ color: LAVENDER, transparent: true, opacity: 0.18, depthWrite: false });
    const shieldMesh = new THREE.LineSegments(edges, shieldMat);
    // rootGroup.add(shieldMesh);

    // Controls state
    let isPaused = false;
    let currentDemoStep = 0;
    let isDragging = false;
    let prevMouseX = 0;
    let prevMouseY = 0;
    let rotSpeedX = 0;
    let rotSpeedY = 0;

    // Interaction handlers
    container.addEventListener('mousedown', (e) => {
      isDragging = true;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    });

    window.addEventListener('mouseup', () => { isDragging = false; });
    window.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      const dx = e.clientX - prevMouseX;
      const dy = e.clientY - prevMouseY;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
      rootGroup.rotation.y += dx * 0.006;
      rootGroup.rotation.x += dy * 0.006;
      rotSpeedX = dx * 0.003;
      rotSpeedY = dy * 0.003;
    });

    // Touch support
    container.addEventListener('touchstart', (e) => {
      if (e.touches.length === 1) {
        isDragging = true;
        prevMouseX = e.touches[0].clientX;
        prevMouseY = e.touches[0].clientY;
      }
    }, { passive: true });

    window.addEventListener('touchend', () => { isDragging = false; });
    window.addEventListener('touchmove', (e) => {
      if (!isDragging || e.touches.length !== 1) return;
      const dx = e.touches[0].clientX - prevMouseX;
      const dy = e.touches[0].clientY - prevMouseY;
      prevMouseX = e.touches[0].clientX;
      prevMouseY = e.touches[0].clientY;
      rootGroup.rotation.y += dx * 0.006;
      rootGroup.rotation.x += dy * 0.006;
    }, { passive: true });

    // UI Overlay controls
    injectControls(container, {
      togglePause: () => {
        isPaused = !isPaused;
        return isPaused;
      },
      nextDemoStep: () => {
        currentDemoStep = (currentDemoStep + 1) % (DEMO_STEPS.length + 1);
        updateDemoUI(currentDemoStep);
      },
      resetDemo: () => {
        currentDemoStep = 0;
        updateDemoUI(0);
      }
    });

    // Animation Loop
    let clock = 0;
    function animate() {
      requestAnimationFrame(animate);

      if (!isPaused) {
        clock += 0.016;
        if (!isDragging) {
          rootGroup.rotation.y += 0.0025 + rotSpeedX;
          rootGroup.rotation.x += rotSpeedY;
          rotSpeedX *= 0.94;
          rotSpeedY *= 0.94;
        }

        shieldMesh.rotation.y -= 0.001;
        shieldMesh.rotation.x += 0.0008;

        // Pulse arcs
        arcsData.forEach((a) => {
          const progress = ((clock + a.offset) % 6) / 6;
          const pt = a.curve.getPoint(Math.min(0.99, progress));
          a.dot.position.copy(pt);
        });

        // Node halo pulse
        nodeMeshes.forEach((grp, idx) => {
          const s = 1 + 0.22 * Math.sin(clock * 3 + idx);
          grp.userData.halo.scale.setScalar(s);
        });
      }

      renderer.render(scene, camera);
    }

    animate();

    // Window Resize
    window.addEventListener('resize', () => {
      const nw = container.clientWidth || 540;
      const nh = container.clientHeight || 540;
      camera.aspect = nw / nh;
      camera.updateProjectionMatrix();
      renderer.setSize(nw, nh);
    });
  }

  function renderFallback(container) {
    container.innerHTML = `
      <div class="globe-fallback-wrap" style="position:relative;width:100%;height:100%;display:grid;place-items:center;">
        <svg viewBox="0 0 400 400" style="width:100%;max-width:440px;height:auto;" aria-label="BrandSentra 2D Perimeter Globe">
          <defs>
            <radialGradient id="gf-body" cx="38%" cy="35%" r="70%"><stop offset="0" stop-color="#3e2f5c"/><stop offset="1" stop-color="#140d20"/></radialGradient>
            <radialGradient id="gf-glow" cx="50%" cy="50%" r="50%"><stop offset=".7" stop-color="#9a83e8" stop-opacity="0"/><stop offset=".82" stop-color="#9a83e8" stop-opacity=".35"/><stop offset="1" stop-color="#9a83e8" stop-opacity="0"/></radialGradient>
            <pattern id="gf-dots" width="7" height="7" patternUnits="userSpaceOnUse"><circle cx="3.5" cy="3.5" r="1.1" fill="#b6a4ff" fill-opacity=".45"/></pattern>
            <clipPath id="gf-clip"><circle cx="200" cy="200" r="120"/></clipPath>
          </defs>
          <circle cx="200" cy="200" r="155" fill="url(#gf-glow)"/>
          <circle cx="200" cy="200" r="120" fill="url(#gf-body)"/>
          <g clip-path="url(#gf-clip)" opacity=".95">
            <ellipse cx="150" cy="150" rx="70" ry="46" fill="url(#gf-dots)"/>
            <ellipse cx="250" cy="190" rx="55" ry="70" fill="url(#gf-dots)"/>
            <ellipse cx="180" cy="255" rx="40" ry="28" fill="url(#gf-dots)"/>
            <ellipse cx="275" cy="120" rx="32" ry="22" fill="url(#gf-dots)"/>
          </g>
          <polygon points="200,58 320,128 320,272 200,342 80,272 80,128" fill="none" stroke="#b6a4ff" stroke-opacity=".25" stroke-dasharray="4 4"/>
          <circle cx="160" cy="160" r="4" fill="#b6a4ff"><animate attributeName="r" values="3;7;3" dur="2s" repeatCount="indefinite"/></circle>
          <circle cx="260" cy="180" r="4" fill="#f2cb55"><animate attributeName="r" values="3;7;3" dur="2.4s" repeatCount="indefinite"/></circle>
          <circle cx="210" cy="240" r="4" fill="#ff7a72"><animate attributeName="r" values="3;7;3" dur="2.2s" repeatCount="indefinite"/></circle>
        </svg>
      </div>`;
  }

  function injectControls(container, api) {
    const parent = container.parentElement;
    if (!parent) return;

    let ctrl = parent.querySelector('.earth-controls');
    if (ctrl) ctrl.remove();

    ctrl = document.createElement('div');
    ctrl.className = 'earth-controls';
    ctrl.innerHTML = `
      <div style="position:absolute;bottom:14px;left:50%;transform:translateX(-50%);display:flex;align-items:center;gap:6px;padding:4px 8px;border-radius:99px;background:rgba(23,15,36,0.85);border:1px solid var(--border);backdrop-filter:blur(10px);z-index:20;box-shadow:0 8px 24px rgba(0,0,0,0.4)">
        <button id="earthPauseBtn" class="earth-c-btn" style="width:32px;height:32px;border-radius:50%;border:none;background:transparent;color:var(--text);cursor:pointer;display:grid;place-items:center;" title="Pause globe rotation">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>
        </button>
        <button id="earthDemoBtn" class="earth-c-btn" style="height:32px;padding:0 12px;border-radius:99px;border:none;background:var(--cyan-glow);color:var(--cyan);font-weight:700;font-size:0.75rem;cursor:pointer;display:flex;align-items:center;gap:6px;" title="Demonstrate how protection works">
           Protection Walkthrough
        </button>
      </div>
      <div id="earthCaptionCard" style="display:none;position:absolute;left:16px;top:16px;max-width:280px;padding:14px;border-radius:12px;background:rgba(23,15,36,0.92);border:1px solid var(--border);backdrop-filter:blur(12px);color:var(--text);z-index:20;box-shadow:var(--shadow);">
        <div id="earthStepBadge" style="font-size:0.65rem;font-weight:700;color:var(--signal);text-transform:uppercase;letter-spacing:0.1em;margin-bottom:4px;">Step 1 of 4</div>
        <div id="earthStepTitle" style="font-weight:700;font-size:0.95rem;margin-bottom:4px;">Register the baseline</div>
        <div id="earthStepBody" style="font-size:0.78rem;color:var(--text-dim);line-height:1.45;">Official website, social accounts, company pages, apps and support channels form the trusted reference.</div>
      </div>
    `;

    parent.appendChild(ctrl);

    const pauseBtn = ctrl.querySelector('#earthPauseBtn');
    const demoBtn = ctrl.querySelector('#earthDemoBtn');

    pauseBtn.addEventListener('click', () => {
      const paused = api.togglePause();
      pauseBtn.innerHTML = paused
        ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>'
        : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>';
    });

    demoBtn.addEventListener('click', () => {
      api.nextDemoStep();
    });
  }

  function updateDemoUI(step) {
    const card = document.getElementById('earthCaptionCard');
    const demoBtn = document.getElementById('earthDemoBtn');
    if (!card) return;

    if (step === 0) {
      card.style.display = 'none';
      if (demoBtn) demoBtn.innerHTML = ' Protection Walkthrough';
      return;
    }

    card.style.display = 'block';
    const s = DEMO_STEPS[step - 1];
    document.getElementById('earthStepBadge').textContent = `Step ${step} of ${DEMO_STEPS.length}`;
    document.getElementById('earthStepTitle').textContent = s.title;
    document.getElementById('earthStepBody').textContent = s.body;
    if (demoBtn) demoBtn.innerHTML = `Next: Step ${step === 4 ? 1 : step + 1} ->`;
  }

  window.initBrandSentraEarth = initEarth;
})();
