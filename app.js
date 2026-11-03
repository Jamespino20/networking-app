// ============================================================
// IP MATH ENGINE
// ============================================================
const IP = {
  toInt(ip) {
    const p = ip.split('.').map(Number);
    return p[0]*16777216 + p[1]*65536 + p[2]*256 + p[3];
  },
  toString(n) {
    return ((n>>>24)&255)+'.'+((n>>>16)&255)+'.'+((n>>>8)&255)+'.'+(n&255);
  },
  getClass(ip) {
    const f = parseInt(ip.split('.')[0]);
    if(f<128) return 'A';
    if(f<192) return 'B';
    if(f<224) return 'C';
    if(f<240) return 'D';
    return 'E';
  },
  getDefaultMask(cls) {
    return {A:'255.0.0.0',B:'255.255.0.0',C:'255.255.255.0'}[cls]||'';
  },
  getDefaultCIDR(cls) {
    return {A:8,B:16,C:24}[cls]||0;
  },
  maskFromCIDR(cidr) {
    if(cidr===0) return 0;
    return (~((1<<(32-cidr))-1))>>>0;
  },
  cidrFromMask(mask) {
    const n = this.toInt(mask);
    let c=0, v=n;
    while(v&0x80000000){c++;v<<=1;v>>>=0;}
    return c;
  },
  wildcardFromMask(mask) {
    return this.toString(this.toInt(mask)^0xFFFFFFFF);
  },
  networkAddr(ip, mask) {
    return this.toString(this.toInt(ip)&this.toInt(mask));
  },
  broadcastAddr(ip, mask) {
    return this.toString((this.toInt(ip)|(~this.toInt(mask)>>>0))>>>0);
  },
  nextSubnet(ip, mask) {
    const n = (this.toInt(ip) + (~this.toInt(mask)>>>0) + 1)>>>0;
    return this.toString(n);
  },
  numHosts(cidr) {
    if(cidr===32) return 1;
    if(cidr===31) return 2; // RFC 3021: /31 = 2 usable hosts
    return Math.pow(2,32-cidr)-2;
  },
  usableHosts(cidr) {
    if(cidr===31) return 2;
    return Math.max(0, Math.pow(2,32-cidr)-2);
  },
  minCIDR(hosts) {
    if(hosts<=2) return 30; // /30 for point-to-point (Packet Tracer compatible)
    if(hosts<=6) return 29;
    return 32-Math.ceil(Math.log2(hosts+2));
  },
  formatRange(ip, mask) {
    const n = this.toInt(ip);
    const m = this.toInt(mask);
    const net = n&m;
    const bcast = (n|(~m>>>0))>>>0;
    if(this.cidrFromMask(mask)===31) return this.toString(net)+' - '+this.toString(net+1);
    return this.toString(net+1)+' - '+this.toString(bcast-1);
  },
  // Check if two CIDR ranges overlap
  overlaps(net1, cidr1, net2, cidr2) {
    const a1 = this.toInt(net1);
    const a2 = this.toInt(net2);
    const mask1 = this.maskFromCIDR(cidr1);
    const mask2 = this.maskFromCIDR(cidr2);
    const base1 = a1 & mask1;
    const base2 = a2 & mask2;
    // They overlap if either network falls within the other's block
    if((a1 & mask2) === base2) return true;
    if((a2 & mask1) === base1) return true;
    return false;
  },
  // Validate an IP is usable in a subnet
  isValidHost(ip, net, cidr) {
    const ipInt = this.toInt(ip);
    const netInt = this.toInt(net);
    const mask = this.maskFromCIDR(cidr);
    const base = netInt & mask;
    const broadcast = (base | (~mask>>>0))>>>0;
    if(cidr===31) return ipInt===base || ipInt===base+1;
    return ipInt!==base && ipInt!==broadcast && (ipInt & mask)===base;
  },
  // Parse "ip/cidr" or just "ip" (defaults to /24)
  parseCIDR(str) {
    str = str.trim();
    if(str.includes('/')) {
      const [ip, cidr] = str.split('/');
      return {ip, cidr: parseInt(cidr)};
    }
    return {ip: str, cidr: 24};
  }
};

// ============================================================
// TAB NAVIGATION
// ============================================================
function activateTab(t){
  document.querySelectorAll('.tab').forEach(x=>{x.classList.remove('active');x.setAttribute('aria-selected','false');});
  document.querySelectorAll('.panel').forEach(x=>x.classList.remove('active'));
  t.classList.add('active');
  t.setAttribute('aria-selected','true');
  document.getElementById(t.dataset.tab).classList.add('active');
}
document.querySelectorAll('.tab').forEach(t=>{
  t.addEventListener('click',()=>activateTab(t));
  t.addEventListener('keydown',e=>{
    if(e.key==='Enter'||e.key===' '){e.preventDefault();activateTab(t);}
    if(e.key==='ArrowRight'||e.key==='ArrowLeft'){
      e.preventDefault();
      const tabs=[...document.querySelectorAll('.tab')];
      let i=tabs.indexOf(t)+(e.key==='ArrowRight'?1:-1);
      i=(i+tabs.length)%tabs.length;
      tabs[i].focus();activateTab(tabs[i]);
    }
  });
});

// ============================================================
// FLSM CALCULATOR
// ============================================================
function calcFLSM() {
  const net = document.getElementById('flsm-net').value.trim();
  const needed = parseInt(document.getElementById('flsm-subnets').value);
  if(!net||!needed) return alert('Fill in all fields');

  const cls = IP.getClass(net);
  const defaultCIDR = IP.getDefaultCIDR(cls);
  const defaultMask = IP.getDefaultMask(cls);

  document.getElementById('flsm-class').innerHTML = `Class ${cls} <span class="tag tag-blue">${cls==='A'?'First octet: 1-126':cls==='B'?'First octet: 128-191':'First octet: 192-223'}</span>`;
  document.getElementById('flsm-default-mask').textContent = defaultMask + ' /' + defaultCIDR;

  const bits = Math.ceil(Math.log2(needed));
  const newCIDR = defaultCIDR + bits;
  if(newCIDR > 31) return alert('Not enough host bits remaining');

  const totalSubs = Math.pow(2, bits);
  const hostsEach = IP.numHosts(newCIDR);
  const blockSize = Math.pow(2, 32-newCIDR);

  document.getElementById('flsm-bits').textContent = bits;
  document.getElementById('flsm-cidr').textContent = '/' + newCIDR + ' (' + IP.toString(IP.maskFromCIDR(newCIDR)) + ')';
  document.getElementById('flsm-total').textContent = totalSubs + ' (required: ' + needed + ')';
  document.getElementById('flsm-hosts').textContent = hostsEach;

  const tbody = document.getElementById('flsm-table');
  tbody.innerHTML = '';
  let current = IP.toInt(net);
  for(let i=0; i<totalSubs; i++) {
    const row = document.createElement('tr');
    const subnet = IP.toString(current);
    const bcast = IP.toString((current + blockSize - 1)>>>0);
    let range;
    if(newCIDR===31) {
      range = IP.toString(current) + ' - ' + IP.toString((current+1)>>>0);
    } else {
      range = IP.toString((current+1)>>>0) + ' - ' + IP.toString((current+blockSize-2)>>>0);
    }
    row.innerHTML = `<td>${i+1}</td><td class="mono">${subnet}/${newCIDR}</td><td class="mono">${range}</td><td class="mono">${bcast}</td>`;
    tbody.appendChild(row);
    current += blockSize;
  }

  document.getElementById('flsm-results').classList.remove('hidden');
}

// ============================================================
// VLSM CALCULATOR
// ============================================================
function addVlsmReq(name='', hosts='') {
  const div = document.createElement('div');
  div.className = 'subnet-row';
  div.innerHTML = `
    <div><label>Name</label><input type="text" value="${name}" class="vlsm-name"></div>
    <div><label>Hosts</label><input type="number" value="${hosts}" class="vlsm-hosts" min="1"></div>
    <div><label>CIDR</label><input type="text" class="vlsm-cidr" readonly></div>
    <div><button class="btn btn-red btn-sm" onclick="removeVlsmReq(this)">X</button></div>`;
  document.getElementById('vlsm-reqs').appendChild(div);
}
function removeVlsmReq(btn) { btn.closest('.subnet-row').remove(); }
function toggleVlsmNetMode() {
  const mode = document.querySelector('input[name="vlsm-net-mode"]:checked').value;
  document.getElementById('vlsm-net-single').style.display = mode==='single' ? 'block' : 'none';
  document.getElementById('vlsm-net-multi').style.display = mode==='multi' ? 'block' : 'none';
}

function calcVLSM() {
  // Parse available networks from single or multi mode
  const mode = document.querySelector('input[name="vlsm-net-mode"]:checked').value;
  let netsText;
  if(mode==='single') {
    netsText = document.getElementById('vlsm-net-single-input').value.trim();
  } else {
    netsText = document.getElementById('vlsm-nets').value.trim();
  }
  if(!netsText) return alert('Enter at least one available network');

  const availableNets = netsText.split('\n').map(line=>{
    const {ip, cidr} = IP.parseCIDR(line.trim());
    return {ip, cidr, size: Math.pow(2, 32-cidr), base: IP.toInt(ip)};
  }).filter(n => n.ip);

  if(availableNets.length===0) return alert('No valid networks entered');

  // DON'T sort by size — keep user order for round-robin distribution

  // Collect requirements
  const reqs = [];
  document.querySelectorAll('#vlsm-reqs .subnet-row').forEach(row=>{
    const name = row.querySelector('.vlsm-name').value.trim();
    const hosts = parseInt(row.querySelector('.vlsm-hosts').value);
    if(name && hosts>0) {
      const cidr = IP.minCIDR(hosts);
      const usable = IP.numHosts(cidr);
      row.querySelector('.vlsm-cidr').value = '/' + cidr + ' (' + usable + ' hosts)';
      reqs.push({name, hosts, cidr, usable});
    }
  });

  if(reqs.length===0) return alert('Add at least one subnet requirement');

  // Sort requirements largest first (most hosts = largest block)
  reqs.sort((a,b)=>b.hosts-a.hosts);

  // Calculate total addresses needed
  const totalNeeded = reqs.reduce((sum, r)=>sum+Math.pow(2,32-r.cidr), 0);
  const totalAvailable = availableNets.reduce((sum, n)=>sum+n.size, 0);

  // Allocate subnets: try each available network in order
  const tbody = document.getElementById('vlsm-table');
  tbody.innerHTML = '';
  const warnings = [];
  const allocated = [];

  // Track next available position in each network
  const netPositions = availableNets.map(n => n.base);

  // Store allocation data globally for manual reassignment
  window._vlsmAvailableNets = availableNets;
  window._vlsmReqs = reqs;
  window._vlsmAllocRows = [];

  // Smart allocation: largest subnet -> largest network, then pack-then-move from network 0
  const largestNetIdx = availableNets.reduce((best,n,i) => n.size > availableNets[best].size ? i : best, 0);
  let netIdx = 0;

  function buildNetOpts(selectedNi) {
    return availableNets.map((n,i) => {
      const sizeStr = n.size >= 1048576 ? (n.size/1048576)+'M' : n.size >= 1024 ? (n.size/1024)+'K' : n.size;
      return '<option value="'+i+'"'+(i===selectedNi?' selected':'')+'>'+n.ip+'/'+n.cidr+' ('+sizeStr+')</option>';
    }).join('');
  }

  function makeRow(req, ni, pos, block) {
    const availNet = availableNets[ni];
    const subnet = IP.toString(pos);
    const mask = IP.toString(IP.maskFromCIDR(req.cidr));
    const wildcard = IP.wildcardFromMask(mask);
    const bcast = IP.toString((pos + block - 1)>>>0);
    let range;
    if(req.cidr===31) range = IP.toString(pos)+' - '+IP.toString((pos+1)>>>0);
    else range = IP.toString((pos+1)>>>0)+' - '+IP.toString((pos+block-2)>>>0);
  const fromBlock = availNet.ip+'/'+availNet.cidr;
    return {subnet, mask, wildcard, bcast, range, fromBlock, ni, pos, block};
  }

  function checkOverlap(name, cidr, pos, block, excludeIdx) {
    for(let k=0; k<window._vlsmAllocRows.length; k++) {
      if(k===excludeIdx) continue;
      const other = window._vlsmAllocRows[k];
      if(!other) continue;
      const otherBlock = Math.pow(2, 32-other.cidr);
      if(pos < other.pos + otherBlock && pos + block > other.pos) return other.name;
    }
    return null;
  }

  window.renderTable = function() {
    const tbody = document.getElementById('vlsm-table');
    tbody.innerHTML = '';
    const warnings = [];
    window._vlsmAllocRows.forEach((r, idx) => {
      if(!r) return;
      const availNet = availableNets[r.ni];
      const req = reqs[idx];
      const row = document.createElement('tr');

      // Check fit
      const availEnd = availNet.base + availNet.size;
      const fits = r.pos + r.block <= availEnd;
      // Check overlap
      const overlapWith = checkOverlap(req.name, req.cidr, r.pos, r.block, idx);

      let netClass = '';
      let flag = '';
      if(!fits) { netClass = 'style="background:var(--red);color:#fff"'; flag = ' <span title="Does not fit in this network">!</span>'; }
      else if(overlapWith) { netClass = 'style="background:#b45309;color:#fff"'; flag = ' <span title="Overlaps with '+overlapWith+'">!</span>'; }

      row.innerHTML = '<td><strong>'+req.name+'</strong></td><td>'+req.hosts+'</td><td>'+req.usable+'</td><td>/'+req.cidr+'</td><td class="mono">'+r.mask+'</td><td class="mono">'+r.subnet+'</td><td class="mono">'+r.wildcard+'</td><td class="mono">'+r.range+'</td><td class="mono">'+r.bcast+'</td><td '+netClass+'><select class="vlsm-net-sel" data-idx="'+idx+'" onchange="reassignVlsmNet(this)">'+buildNetOpts(r.ni)+'</select>'+flag+'</td>';
      tbody.appendChild(row);

      if(!fits) warnings.push(req.name+' does not fit in '+availNet.ip+'/'+availNet.cidr);
      if(overlapWith) warnings.push('OVERLAP: '+req.name+' ('+r.subnet+'/'+req.cidr+') overlaps with '+overlapWith);
    });

    const warnDiv = document.getElementById('vlsm-warnings');
    const warnList = document.getElementById('vlsm-warnings-list');
    if(warnings.length>0) {
      warnDiv.style.display = 'block';
      warnList.innerHTML = warnings.map(w=>'<p style="color:var(--red);margin:4px 0">\u26a0 '+w+'</p>').join('');
    } else {
      warnDiv.style.display = 'none';
    }

    // Network usage bars
    const usageDiv = document.getElementById('vlsm-net-usage');
    let usageHtml = '<h3 class="rb-title" style="margin-top:16px;margin-bottom:8px">Network Usage</h3>';
    availableNets.forEach((n, ni) => {
      const used = window._vlsmAllocRows.filter(r => r && r.ni === ni).reduce((sum, r) => sum + r.block, 0);
      const pct = Math.round(used / n.size * 100);
      const barColor = pct > 90 ? 'var(--red)' : pct > 70 ? 'var(--yellow)' : 'var(--green)';
      const usedStr = used >= 1048576 ? (used/1048576).toFixed(1)+'M' : used >= 1024 ? (used/1024).toFixed(1)+'K' : used;
      const totalStr = n.size >= 1048576 ? (n.size/1048576).toFixed(0)+'M' : n.size >= 1024 ? (n.size/1024).toFixed(0)+'K' : n.size;
      const count = window._vlsmAllocRows.filter(r => r && r.ni === ni).length;
      usageHtml += '<div class="net-usage-bar"><span class="bar-label"><strong>'+n.ip+'/'+n.cidr+'</strong> ('+count+' subnets)</span><div class="bar-track"><div class="bar-fill" style="width:'+pct+'%;background:'+barColor+'"></div></div><span class="bar-pct">'+usedStr+'/'+totalStr+' ('+pct+'%)</span></div>';
    });
    usageDiv.innerHTML = usageHtml;
  }

  // Initial allocation
  const fullNets = new Set();
  for(let ri=0; ri<reqs.length; ri++) {
    const req = reqs[ri];
    const block = Math.pow(2, 32-req.cidr);
    let placed = false;

    // Try each network
    for(let attempt=0; attempt<availableNets.length; attempt++) {
      const ni = (ri===0 ? largestNetIdx : netIdx) + attempt;
      const niMod = ni % availableNets.length;
      if(fullNets.has(niMod)) continue;
      const net = availableNets[niMod];
      const availEnd = net.base + net.size;

      // Find first aligned position that fits within the network
      let pos = netPositions[niMod] !== undefined ? netPositions[niMod] : net.base;
      if(pos < net.base) pos = net.base;
      if(pos % block !== 0) pos = pos + block - (pos % block);

      // If subnet is too large for this network, skip it
      if(block > net.size) {
        fullNets.add(niMod);
        continue;
      }

      // FIX: Single-block connections can create their own WANs
      // If this is a /30 or smaller, it can use the network itself
      // This allows /30 links to be standalone without being part of a larger network
      if(block === 4 && net.size >= 4 && netPositions[niMod] === undefined) {
        const r = makeRow(req, niMod, net.base, block);
        window._vlsmAllocRows[ri] = r;
        allocated[ri] = {name:req.name, subnet:r.subnet, cidr:req.cidr, mask:r.mask, block, fromBlock:r.fromBlock};
        netPositions[niMod] = (net.base + block)>>>0;
        netIdx = niMod;
        placed = true;
        break;
      }

      let networkFull = false;
      while(pos + block <= availEnd) {
        // Check overlap with existing allocations AND network boundary
        let blocked = false;
        for(let k=0; k<window._vlsmAllocRows.length; k++) {
          if(k===ri) continue;
          const other = window._vlsmAllocRows[k];
          if(!other) continue;
          const otherBlock = Math.pow(2, 32-reqs[k].cidr);
          if(pos < other.pos + otherBlock && pos + block > other.pos) { blocked = true; pos = (other.pos + otherBlock); if(pos % block !== 0) pos = pos + block - (pos % block); break; }
        }
        if(!blocked) {
          const r = makeRow(req, niMod, pos, block);
          window._vlsmAllocRows[ri] = r;
          allocated[ri] = {name:req.name, subnet:r.subnet, cidr:req.cidr, mask:r.mask, block, fromBlock:r.fromBlock};
          netPositions[niMod] = (pos + block)>>>0;
          netIdx = niMod;
          placed = true;
          break;
        }
      }
      if(!placed && !networkFull) {
        // While loop exited = no space left in this network
        fullNets.add(niMod);
        networkFull = true;
      }
      if(placed) break;
    }

    // Auto-expand for single mode
    if(!placed && mode==='single' && availableNets.length > 0) {
      const lastNet = availableNets[availableNets.length - 1];
      const nextBase = (lastNet.base + lastNet.size)>>>0;
      const nextIp = IP.toString(nextBase);
      const nextNet = {ip:nextIp, cidr:lastNet.cidr, size:lastNet.size, base:nextBase};
      availableNets.push(nextNet);
      netPositions.push(nextBase);
      window._vlsmAvailableNets = availableNets;
      const ni = availableNets.length - 1;
      let pos = nextBase;
      if(pos % block !== 0) pos = pos + block - (pos % block);
      if(pos + block <= nextBase + nextNet.size) {
        const r = makeRow(req, ni, pos, block);
        window._vlsmAllocRows[ri] = r;
        allocated[ri] = {name:req.name, subnet:r.subnet, cidr:req.cidr, mask:r.mask, block, fromBlock:r.fromBlock};
        netPositions[ni] = (pos + block)>>>0;
        netIdx = ni;
        placed = true;
      }
    }
    if(!placed) window._vlsmAllocRows[ri] = null;
  }

  renderTable();

  // Check for overlaps
  for(let i=0;i<allocated.length;i++) {
    for(let j=i+1;j<allocated.length;j++) {
      if(IP.overlaps(allocated[i].subnet, allocated[i].cidr, allocated[j].subnet, allocated[j].cidr)) {
        warnings.push(`OVERLAP: ${allocated[i].name} (${allocated[i].subnet}/${allocated[i].cidr}) overlaps with ${allocated[j].name} (${allocated[j].subnet}/${allocated[j].cidr})`);
      }
    }
  }

  // Show/hide warnings
  const warnDiv = document.getElementById('vlsm-warnings');
  const warnList = document.getElementById('vlsm-warnings-list');
  if(warnings.length>0) {
    warnDiv.style.display = 'block';
    warnList.innerHTML = warnings.map(w=>`<p style="color:var(--red);margin:4px 0">⚠ ${w}</p>`).join('');
  } else {
    warnDiv.style.display = 'none';
  }

  // Summary
  const totalAllocated = allocated.reduce((sum,a)=>sum+a.block, 0);
  const summaryDiv = document.getElementById('vlsm-summary');
  summaryDiv.innerHTML = `<h3 class="rb-title">Summary</h3>
    <p>Total addresses needed: <strong>${totalNeeded}</strong> | Available: <strong>${totalAvailable}</strong> | Allocated: <strong>${totalAllocated}</strong> | Remaining: <strong>${totalAvailable - totalAllocated}</strong></p>
    <p>Subnets allocated: <strong>${allocated.length}</strong> of ${reqs.length} requested</p>`;

  // Save for topology use
  window._vlsmSubnets = allocated;
  window._vlsmReqs = reqs;
  document.getElementById('vlsm-results').classList.remove('hidden');
}


function reassignVlsmNet(sel) {
  const idx = parseInt(sel.dataset.idx);
  const newNi = parseInt(sel.value);
  const req = window._vlsmReqs[idx];
  const block = Math.pow(2, 32-req.cidr);

  // Find next aligned position that doesn't overlap
  const net = window._vlsmAvailableNets[newNi];
  const availEnd = net.base + net.size;
  let pos = net.base;
  const others = window._vlsmAllocRows
    .filter((r,i) => r && r.ni===newNi && i!==idx)
    .sort((a,b)=>a.pos-b.pos);

  while(pos + block <= availEnd) {
    // Align
    if(pos % block !== 0) pos = pos + block - (pos % block);
    // Check overlap
    let overlaps = false;
    for(const r of others) {
      const rEnd = (r.pos + r.block)>>>0;
      if(pos < rEnd && pos + block > r.pos) { overlaps = true; pos = rEnd; if(pos % block !== 0) pos = pos + block - (pos % block); break; }
    }
    if(!overlaps) break;
  }

  const mask = IP.toString(IP.maskFromCIDR(req.cidr));
  const wildcard = IP.wildcardFromMask(mask);
  const subnet = IP.toString(pos);
  const bcast = IP.toString((pos + block - 1)>>>0);
  let range;
  if(req.cidr===31) range = IP.toString(pos)+' - '+IP.toString((pos+1)>>>0);
  else range = IP.toString((pos+1)>>>0)+' - '+IP.toString((pos+block-2)>>>0);
  const fromBlock = net.ip+'/'+net.cidr;

  window._vlsmAllocRows[idx] = {subnet, mask, wildcard, bcast, range, fromBlock, ni:newNi, pos, block};

  // Rebuild allocated array and re-render
  const allocated = [];
  window._vlsmAllocRows.forEach((r,i) => {
    if(r) allocated.push({name:window._vlsmReqs[i].name, subnet:r.subnet, cidr:window._vlsmReqs[i].cidr, mask:r.mask, block:Math.pow(2,32-window._vlsmReqs[i].cidr), fromBlock:r.fromBlock});
  });
  window._vlsmSubnets = allocated;
  window.renderTable();
}

function sendVlsmToTopology() {
  if(!window._vlsmSubnets || window._vlsmSubnets.length===0) return alert('Calculate VLSM first');

  topo = { routers: [], interfaces: [], links: [], lans: [] };

  const wanSubnets = window._vlsmSubnets.filter(s => s.name.toUpperCase().includes('WAN'));
  const lanSubnets = window._vlsmSubnets.filter(s => !s.name.toUpperCase().includes('WAN'));

  const routerNames = new Set();
  wanSubnets.forEach(w => {
    const m = w.name.toUpperCase().match(/R\d+/g);
    if(m) m.forEach(r => routerNames.add(r));
  });
  if(routerNames.size===0) routerNames.add('R1');
  [...routerNames].sort().forEach(n => topo.routers.push({name:n}));

  wanSubnets.forEach(w => {
    const m = w.name.toUpperCase().match(/R(\d+).*R(\d+)/);
    if(!m) return;
    const rA = 'R'+m[1], rB = 'R'+m[2];
    const getSer = (r) => {
      for(let i=0;i<10;i++){const t='S0/0/'+i;if(!topo.interfaces.some(x=>x.router===r&&x.name===t))return t;}
      return 'S0/0/0';
    };
    const iA=getSer(rA), iB=getSer(rB);
    const n=IP.toInt(w.subnet), mask=IP.toString(IP.maskFromCIDR(w.cidr));
    const ipA=IP.toString((n+1)>>>0), ipB=IP.toString((n+2)>>>0);
    updateOrCreateIface(rA,iA,'WAN',ipA,mask,w.subnet+'/'+w.cidr);
    updateOrCreateIface(rB,iB,'WAN',ipB,mask,w.subnet+'/'+w.cidr);
    topo.links.push({a:{router:rA,iface:iA,ip:ipA,dce:true},b:{router:rB,iface:iB,ip:ipB,dce:false},network:w.subnet+'/'+w.cidr});
  });

  const routers = topo.routers.map(r=>r.name);
  lanSubnets.forEach((l,idx)=>{
    const router = routers[idx%routers.length];
    const n=IP.toInt(l.subnet), mask=IP.toString(IP.maskFromCIDR(l.cidr));
    const rIP=IP.toString((n+1)>>>0);
    const used=topo.interfaces.filter(i=>i.router===router).map(i=>i.name);
    let iface='Fa0/0';
    for(let i=0;i<10;i++){const t='Fa0/'+i;if(!used.includes(t)){iface=t;break;}}
    updateOrCreateIface(router,iface,'LAN',rIP,mask,l.subnet+'/'+l.cidr);
    // No placeholder hosts: PCs attach bottom-up and servers top-down in Devices in LAN,
    // so nothing squats on the addresses the other side needs.
    topo.lans.push({router,iface,network:l.subnet+'/'+l.cidr,routerIP:rIP,mask,hosts:[]});
  });

  const refDiv = document.getElementById('vlsm-ref');
  const refTable = document.getElementById('vlsm-ref-table');
  refDiv.style.display='block';
  let html='<table><thead><tr><th>Name</th><th>CIDR</th><th>Network</th><th>Range</th><th>Broadcast</th></tr></thead><tbody>';
  window._vlsmSubnets.forEach(s=>{
    const si=IP.toInt(s.subnet);
    const range=s.cidr===31?IP.toString(si)+' - '+IP.toString((si+1)>>>0):IP.toString((si+1)>>>0)+' - '+IP.toString((si+s.block-2)>>>0);
    html+='<tr><td><strong>'+s.name+'</strong></td><td>/'+s.cidr+'</td><td class="mono">'+s.subnet+'/'+s.cidr+'</td><td class="mono">'+range+'</td><td class="mono">'+IP.toString((si+s.block-1)>>>0)+'</td></tr>';
  });
  html+='</tbody></table>';
  refTable.innerHTML=html;

  renderTopo();
  document.querySelectorAll('.tab').forEach(x=>{x.classList.remove('active');x.setAttribute('aria-selected','false');});
  document.querySelectorAll('.panel').forEach(x=>x.classList.remove('active'));
  const topoTab=document.querySelector('[data-tab="topo"]');
  topoTab.classList.add('active');
  topoTab.setAttribute('aria-selected','true');
  document.getElementById('topo').classList.add('active');
}


// ============================================================
// TOPOLOGY BUILDER
// ============================================================
let topo = { routers: [], interfaces: [], links: [], lans: [], vlsmSubnets: [] };

function showFieldError(inputId, msg) {
  const el = document.getElementById(inputId);
  if(!el) return;
  el.style.borderColor = 'var(--red)';
  el.title = msg;
  el.focus();
  // Remove error on next input
  const clear = () => { el.style.borderColor = ''; el.title = ''; el.removeEventListener('input', clear); };
  el.addEventListener('input', clear);
  // Also show a brief inline message
  let err = el.parentElement.querySelector('.field-error-msg');
  if(!err) {
    err = document.createElement('div');
    err.className = 'field-error-msg';
    err.style.cssText = 'color:var(--red);font-size:.75rem;margin-top:2px';
    el.parentElement.appendChild(err);
  }
  err.textContent = msg;
  setTimeout(() => { if(err) err.remove(); }, 4000);
}

function addRouter() {
  const name = document.getElementById('new-router-name').value.trim().toUpperCase();
  if(!name) return showFieldError('new-router-name', 'Enter a router name — e.g. R1');
  if(topo.routers.find(r=>r.name===name)) return showFieldError('new-router-name', 'Router "' + name + '" already exists');
  topo.routers.push({name});
  document.getElementById('new-router-name').value = '';
  renderTopo();
}

function addIface() {
  const router = document.getElementById('iface-router').value;
  const name = document.getElementById('iface-name').value.trim();
  const type = document.getElementById('iface-type').value;
  if(!router) return;
  if(!name) return showFieldError('iface-name', 'Enter an interface name — e.g. g0/0');
  topo.interfaces.push({router, name, type, ip:'', mask:'', network:'', connectedTo:''});
  document.getElementById('iface-name').value = '';
  renderTopo();
}

function addLink() {
  const aRouter = document.getElementById('link-a-router').value;
  const aIface = document.getElementById('link-a-iface').value;
  const bRouter = document.getElementById('link-b-router').value;
  const bIface = document.getElementById('link-b-iface').value;
  const network = document.getElementById('link-network').value.trim();
  const ipAInput = document.getElementById('link-ip-a').value.trim();
  const ipBInput = document.getElementById('link-ip-b').value.trim();
  const dceSide = document.getElementById('link-dce').value;
  if(!aRouter||!aIface||!bRouter||!bIface) return;
  if(!network) return showFieldError('link-network', 'Enter the WAN network — e.g. 10.0.0.0/30');

  const [netPart, cidrPart] = parseNetwork(network);
  const cidr = parseInt(cidrPart)||24;
  const mask = IP.toString(IP.maskFromCIDR(cidr));
  const netInt = IP.toInt(netPart);

  // Use custom IPs or auto-assign
  const ipA = ipAInput || IP.toString(netInt + 1);
  const ipB = ipBInput || IP.toString(netInt + 2);

  // Update or create interfaces
  updateOrCreateIface(aRouter, aIface, 'WAN', ipA, mask, netPart+'/'+cidr);
  updateOrCreateIface(bRouter, bIface, 'WAN', ipB, mask, netPart+'/'+cidr);

  topo.links.push({
    a:{router:aRouter, iface:aIface, ip:ipA, dce:dceSide==='a'},
    b:{router:bRouter, iface:bIface, ip:ipB, dce:dceSide==='b'},
    network:netPart+'/'+cidr
  });

  // Clear inputs
  document.getElementById('link-ip-a').value = '';
  document.getElementById('link-ip-b').value = '';
  document.getElementById('link-network').value = '';
  renderTopo();
}

function addLAN() {
  const router = document.getElementById('lan-router').value;
  const iface = document.getElementById('lan-iface').value;
  const network = document.getElementById('lan-network').value.trim();
  const routerIPInput = document.getElementById('lan-router-ip').value.trim();
  if(!router||!iface) return;
  if(!network) return showFieldError('lan-network', 'Enter the LAN network — e.g. 192.168.1.0/24');

  const [netPart, cidrPart] = parseNetwork(network);
  const cidr = parseInt(cidrPart)||24;
  const mask = IP.toString(IP.maskFromCIDR(cidr));
  const netInt = IP.toInt(netPart);

  // Router IP auto-assigns to .1; hosts attach below in Devices in LAN
  const routerIP = routerIPInput || IP.toString(netInt + 1);

  updateOrCreateIface(router, iface, 'LAN', routerIP, mask, netPart+'/'+cidr);

  topo.lans.push({router, iface, network:netPart+'/'+cidr, routerIP, mask, hosts:[]});

  // Clear inputs
  document.getElementById('lan-router-ip').value = '';
  document.getElementById('lan-network').value = '';
  renderTopo();
}

function updateOrCreateIface(router, name, type, ip, mask, network) {
  const existing = topo.interfaces.find(i=>i.router===router&&i.name===name);
  if(existing) {
    existing.ip = ip; existing.mask = mask; existing.network = network; existing.type = type;
  } else {
    topo.interfaces.push({router, name, type, ip, mask, network});
  }
}

function parseNetwork(str) {
  if(str.includes('/')) {
    const parts = str.split('/');
    return [parts[0], parts[1]];
  }
  return [str, '24'];
}

function removeRouter(name) {
  topo.routers = topo.routers.filter(r=>r.name!==name);
  topo.interfaces = topo.interfaces.filter(i=>i.router!==name);
  topo.links = topo.links.filter(l=>l.a.router!==name&&l.b.router!==name);
  topo.lans = topo.lans.filter(l=>l.router!==name);
  renderTopo();
}
function removeIface(router,name) {
  topo.interfaces = topo.interfaces.filter(i=>!(i.router===router&&i.name===name));
  renderTopo();
}
function editIface(router, name) {
  const iface = topo.interfaces.find(i=>i.router===router&&i.name===name);
  if(!iface) return;
  showModal('Edit Interface: '+router+' '+name, [
    {type:'row', fields:[{key:'ip', label:'IP Address', value:iface.ip}, {key:'mask', label:'Subnet Mask', value:iface.mask}]},
    {type:'row', fields:[{key:'network', label:'Network/CIDR', value:iface.network}]},
  ], {type:'iface', router, name});
}
function removeLink(idx) { topo.links.splice(idx,1); renderTopo(); }
function removeLAN(idx) { topo.lans.splice(idx,1); renderTopo(); }

// ============================================================
// DEVICES IN LAN (per-subnetwork topology)
// Each LAN owns its hosts: {name, kind:'pc'|'server', sub, ip}
// ============================================================
function lanHosts(l) {
  if(!l.hosts) {
    // Migrate legacy shape (pcName/pcIP + servers[]) if present
    l.hosts = [];
    if(l.pcIP) l.hosts.push({name: l.pcName || 'PC', kind: 'pc', ip: l.pcIP});
    (l.servers || []).forEach(s=>l.hosts.push({name: s.name, kind: 'server', sub: s.type, ip: s.ip}));
    delete l.pcName; delete l.pcIP; delete l.servers;
  }
  return l.hosts;
}

function refreshDevLanSelect() {
  const sel = document.getElementById('dev-lan');
  if(sel) {
    const cur = sel.value;
    sel.innerHTML = topo.lans.map((l,i)=>`<option value="${i}">${l.router} ${l.iface} · ${l.network} (${lanHosts(l).length} hosts)</option>`).join('');
    if(cur && topo.lans[parseInt(cur)]) sel.value = cur;
    suggestHostIPIntoForm();
  }
  // Service editor follows the attached servers
  const svcSel = document.getElementById('dev-svc-server');
  if(svcSel) {
    const opts = [];
    topo.lans.forEach((l,li)=>lanHosts(l).forEach((h,hi)=>{
      if(h.kind === 'server') opts.push({key: li + ':' + hi, label: `${h.name} (${h.sub} · ${h.ip})`});
    }));
    svcSel.innerHTML = opts.map(o=>`<option value="${o.key}">${o.label}</option>`).join('');
    if(opts.find(o=>o.key === window._svcSel)) { svcSel.value = window._svcSel; }
    else if(opts.length > 0) { window._svcSel = opts[0].key; svcSel.value = opts[0].key; }
    else { window._svcSel = ''; }
    renderSvcForm();
  }
}

function suggestHostIP(lan, kind) {
  // PCs fill from the bottom (.2 upward); servers take the last usable IP, walking down
  const [netPart, cidrPart] = parseNetwork(lan.network || '192.168.1.0/24');
  const cidr = parseInt(cidrPart) || 24;
  const netInt = IP.toInt(netPart);
  const block = Math.pow(2, 32 - cidr);
  const taken = new Set([lan.routerIP, ...(lanHosts(lan).map(h=>h.ip))].filter(Boolean));
  if(kind && kind !== 'PC') {
    for(let h = block - 2; h >= 1; h--) {
      const cand = IP.toString(netInt + h);
      if(!taken.has(cand)) return cand;
    }
    return '';
  }
  for(let h = 2; h < block - 1; h++) {
    const cand = IP.toString(netInt + h);
    if(!taken.has(cand)) return cand;
  }
  return '';
}

function suggestHostIPIntoForm() {
  const sel = document.getElementById('dev-lan');
  const kindSel = document.getElementById('dev-kind');
  const ipInput = document.getElementById('dev-ip');
  if(!sel || !ipInput || ipInput.value.trim()) return;
  const lan = topo.lans[parseInt(sel.value)];
  if(lan) ipInput.placeholder = suggestHostIP(lan, kindSel ? kindSel.value : 'PC') || 'no free host';
}

function findIPHolder(ip) {
  // Returns a label like 'PC1 (R1 Fa0/0)' when an IP is already taken anywhere
  for(const i of topo.interfaces) {
    if(i.ip === ip) return `${i.router} ${i.name} (interface)`;
  }
  for(const l of topo.lans) {
    if(l.routerIP === ip) return `${l.router} ${l.iface} (gateway)`;
    const h = lanHosts(l).find(h=>h.ip===ip);
    if(h) return `${h.name} (${l.router} ${l.iface})`;
  }
  return null;
}

function togglePcCreds() {
  const row = document.getElementById('dev-pc-creds');
  const kind = document.getElementById('dev-kind')?.value;
  if(row) row.style.display = kind === 'PC' ? 'flex' : 'none';
  suggestHostIPIntoForm();
}

function addDeviceToLAN() {
  const lanIdx = parseInt(document.getElementById('dev-lan').value);
  const kind = document.getElementById('dev-kind').value;
  const nameInput = document.getElementById('dev-name');
  const ipInput = document.getElementById('dev-ip');
  const lan = topo.lans[lanIdx];
  if(!lan) return showFieldError('dev-lan', 'Add a LAN first, then attach devices to it');
  const isServer = kind !== 'PC';
  const name = nameInput.value.trim().toUpperCase() || (isServer ? kind.toUpperCase() + '-SRV' : 'PC' + (lanHosts(lan).filter(h=>h.kind==='pc').length + 1));
  if(collectDevices().find(d=>d.name===name)) return showFieldError('dev-name', 'Device "' + name + '" already exists — pick a unique name');
  let ip = ipInput.value.trim() || suggestHostIP(lan, kind);
  if(!ip) return showFieldError('dev-ip', 'No free host left in ' + lan.network);
  // Validate IP sits inside the LAN subnet
  const [netPart, cidrPart] = parseNetwork(lan.network);
  const cidr = parseInt(cidrPart) || 24;
  const netInt = IP.toInt(netPart);
  const block = Math.pow(2, 32 - cidr);
  const ipInt = IP.toInt(ip);
  if(ipInt < netInt + 1 || ipInt > netInt + block - 2) return showFieldError('dev-ip', ip + ' is outside ' + lan.network);
  // Collision check — the bug that put DNS-SRV on top of the PC's .30
  const holder = findIPHolder(ip);
  if(holder) return showFieldError('dev-ip', ip + ' is already taken by ' + holder);

  // PC credentials double as mail/FTP login defaults; servers keep service params instead
  const userName = document.getElementById('dev-user')?.value.trim() || name.toLowerCase();
  const userPass = document.getElementById('dev-pass')?.value || 'cisco';
  lanHosts(lan).push(isServer
    ? {name, kind:'server', sub:kind, ip, svc:svcDefaults(kind, name)}
    : {name, kind:'pc', ip, user:userName, pass:userPass});
  // Jump the service editor straight to the new server
  if(isServer) window._svcSel = lanIdx + ':' + (lanHosts(lan).length - 1);
  nameInput.value = ''; ipInput.value = '';
  if(document.getElementById('dev-user')) document.getElementById('dev-user').value = '';
  if(document.getElementById('dev-pass')) document.getElementById('dev-pass').value = '';
  renderTopo();
}

function svcDefaults(kind, name) {
  if(kind === 'DNS') return {domain:'lab.local', enabled:'on', records:[{name:'www', type:'A Record', val:''}]};
  if(kind === 'HTTP') return {port:'80', https:true};
  if(kind === 'Email') return {domain:'lab.local', smtpOn:'on', pop3On:'on', smtp:'25', pop3:'110', imap:'143', from:'admin@lab.local', to:'user@lab.local', subject:'Test Email', body:'', users:[], usersTouched:false};
  if(kind === 'DHCP') return {pool:(name || 'DHCP').replace(/\s/g,'') + '_pool', gw:'', start:'', mask:'', max:'50', dns:''};
  return {};
}

function findSvcHost() {
  const parts = String(window._svcSel || '').split(':');
  if(parts.length !== 2) return null;
  const lan = topo.lans[parseInt(parts[0])];
  const host = lan ? lanHosts(lan)[parseInt(parts[1])] : null;
  if(!lan || !host || host.kind !== 'server') return null;
  return {lan, host};
}

function escHtml(s) {
  return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function renderSvcForm() {
  const form = document.getElementById('dev-svc-form');
  if(!form) return;
  const found = findSvcHost();
  if(!found) { form.innerHTML = '<p style="color:var(--text2);font-size:.85rem">Attach a server in Devices in LAN to configure its service.</p>'; return; }
  const {lan, host} = found;
  const svc = host.svc = host.svc || svcDefaults(host.sub, host.name);
  const title = `<p class="mono" style="color:var(--cyan);margin-bottom:8px">${escHtml(host.name)} <span class="tag tag-purple">${escHtml(host.sub)}</span> <span class="mono">${escHtml(host.ip)}</span> <span style="color:var(--text2)">· ${escHtml(lan.network)}</span></p>`;

  if(host.sub === 'DNS') {
    const recOpts = ['A Record','CNAME','MX','NS'];
    const rows = (svc.records || []).map(r=>`<div class="subnet-row svc-dns-row">
      <div><label>Name</label><input type="text" class="svc-rec-name" value="${escHtml(r.name)}" placeholder="www"></div>
      <div><label>Type</label><select class="svc-rec-type">${recOpts.map(o=>`<option${o===r.type?' selected':''}>${o}</option>`).join('')}</select></div>
      <div><label>Address</label><input type="text" class="svc-rec-val" value="${escHtml(r.val)}" placeholder="192.168.1.100"></div>
      <div><button class="btn btn-red btn-sm" onclick="this.closest('.svc-dns-row').remove();saveSvcForm()">X</button></div>
    </div>`).join('');
    form.innerHTML = title + `<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end">
      <div><label>Domain Name</label><input type="text" data-svc="domain" value="${escHtml(svc.domain)}" style="width:160px"></div>
      <div><label>DNS Service</label><select data-svc="enabled" style="width:100px"><option value="on"${svc.enabled!=='off'?' selected':''}>On</option><option value="off"${svc.enabled==='off'?' selected':''}>Off</option></select></div>
    </div>
    <label style="margin-top:8px">Resource Records</label><div>${rows}</div>
    <button class="btn btn-sm" style="margin-top:6px" onclick="addSvcDnsRecord()">+ Add Record</button>`;
  } else if(host.sub === 'HTTP') {
    form.innerHTML = title + `<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end">
      <div><label>Port</label><input type="number" data-svc="port" value="${escHtml(svc.port || '80')}" style="width:100px"></div>
      <div><label><input type="checkbox" data-svc="https"${svc.https === false ? '' : ' checked'}> Enable HTTPS</label></div>
    </div>`;
  } else if(host.sub === 'Email') {
    // Mail users are the PCs already in the topology (mirrors PT User Setup list)
    const pcHosts = [];
    topo.lans.forEach(l=>lanHosts(l).forEach(h=>{ if(h.kind === 'pc') pcHosts.push(h); }));
    const userRows = pcHosts.length ? pcHosts.map(h=>{
      const saved = (svc.users || []).find(u=>u.name === h.name);
      const checked = (saved || !svc.usersTouched) ? ' checked' : '';
      const pw = saved ? saved.pass : (h.pass || 'cisco');
      return `<div class="svc-mail-row" style="display:flex;gap:8px;align-items:center;margin:4px 0;flex-wrap:wrap">`
        + `<label style="margin:0;min-width:200px"><input type="checkbox" class="svc-mail-user" value="${escHtml(h.name)}"${checked}> <strong>${escHtml(h.name)}</strong> <span class="mono" style="color:var(--text2)">${escHtml(h.ip)}</span></label>`
        + `<input type="password" class="svc-mail-pass" value="${escHtml(pw)}" placeholder="cisco" style="width:150px">`
        + `</div>`;
    }).join('') : '<p style="color:var(--text2);font-size:.8rem">No PCs in the topology yet — attach PCs in Devices in LAN and they will show up here.</p>';
    form.innerHTML = title + `<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end">
      <div><label>Domain</label><input type="text" data-svc="domain" value="${escHtml(svc.domain)}" style="width:150px"></div>
      <div><label>SMTP Service</label><select data-svc="smtpOn" style="width:90px"><option value="on"${svc.smtpOn !== 'off' ? ' selected' : ''}>ON</option><option value="off"${svc.smtpOn === 'off' ? ' selected' : ''}>OFF</option></select></div>
      <div><label>POP3 Service</label><select data-svc="pop3On" style="width:90px"><option value="on"${svc.pop3On !== 'off' ? ' selected' : ''}>ON</option><option value="off"${svc.pop3On === 'off' ? ' selected' : ''}>OFF</option></select></div>
      <div><label>SMTP Port</label><input type="number" data-svc="smtp" value="${escHtml(svc.smtp)}" style="width:80px"></div>
      <div><label>POP3 Port</label><input type="number" data-svc="pop3" value="${escHtml(svc.pop3)}" style="width:80px"></div>
      <div><label>IMAP Port</label><input type="number" data-svc="imap" value="${escHtml(svc.imap)}" style="width:80px"></div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end;margin-top:8px">
      <div><label>From (sender)</label><input type="text" data-svc="from" value="${escHtml(svc.from)}" style="width:170px"></div>
      <div><label>To (recipient)</label><input type="text" data-svc="to" value="${escHtml(svc.to)}" style="width:170px"></div>
      <div><label>Subject</label><input type="text" data-svc="subject" value="${escHtml(svc.subject)}" style="width:150px"></div>
    </div>
    <div style="margin-top:8px"><label>Body</label><textarea data-svc="body" rows="2" style="width:100%">${escHtml(svc.body)}</textarea></div>
    <label style="margin-top:8px">Mail Users (from topology PCs)</label>${userRows}`;
  } else if(host.sub === 'DHCP') {
    const [netPart] = parseNetwork(lan.network || '192.168.1.0/24');
    form.innerHTML = title + `<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end">
      <div><label>Pool Name</label><input type="text" data-svc="pool" value="${escHtml(svc.pool)}" style="width:150px"></div>
      <div><label>Default Gateway</label><input type="text" data-svc="gw" value="${escHtml(svc.gw)}" placeholder="${escHtml(lan.routerIP)}" style="width:130px"></div>
      <div><label>Start IP</label><input type="text" data-svc="start" value="${escHtml(svc.start)}" placeholder="${escHtml(incrementIP(netPart, 10))}" style="width:130px"></div>
      <div><label>Mask</label><input type="text" data-svc="mask" value="${escHtml(svc.mask)}" placeholder="${escHtml(lan.mask)}" style="width:130px"></div>
      <div><label>Max Users</label><input type="number" data-svc="max" value="${escHtml(svc.max)}" style="width:80px"></div>
      <div><label>DNS Server</label><input type="text" data-svc="dns" value="${escHtml(svc.dns)}" placeholder="= gateway" style="width:130px"></div>
    </div>
    <p style="color:var(--text2);font-size:.75rem;margin-top:6px">Blanks fall back to this LAN (gateway, .10 start, LAN mask) at generate time.</p>`;
  } else {
    form.innerHTML = title + `<p style="color:var(--text2);font-size:.85rem">Generic host — no service parameters. Static IP entry only.</p>`;
  }
}

function saveSvcForm() {
  const found = findSvcHost();
  const form = document.getElementById('dev-svc-form');
  if(!found || !form) return;
  const svc = found.host.svc = found.host.svc || {};
  form.querySelectorAll('[data-svc]').forEach(el=>{
    svc[el.dataset.svc] = el.type === 'checkbox' ? el.checked : el.value;
  });
  if(found.host.sub === 'DNS') {
    svc.records = [];
    form.querySelectorAll('.svc-dns-row').forEach(row=>{
      const name = row.querySelector('.svc-rec-name')?.value.trim();
      const type = row.querySelector('.svc-rec-type')?.value;
      const val = row.querySelector('.svc-rec-val')?.value.trim();
      if(name && val) svc.records.push({name, type, val});
    });
  }
  if(found.host.sub === 'Email') {
    svc.users = []; svc.usersTouched = true;
    form.querySelectorAll('.svc-mail-row').forEach(row=>{
      const cb = row.querySelector('.svc-mail-user');
      if(cb && cb.checked) {
        svc.users.push({name: cb.value, pass: row.querySelector('.svc-mail-pass')?.value || 'cisco'});
      }
    });
  }
}

function addSvcDnsRecord() {
  saveSvcForm();
  const found = findSvcHost();
  if(!found) return;
  found.host.svc.records = found.host.svc.records || [];
  found.host.svc.records.push({name:'', type:'A Record', val:''});
  renderSvcForm();
}

function removeHostFromLAN(lanIdx, hostIdx) {
  const lan = topo.lans[lanIdx];
  if(lan && lanHosts(lan)[hostIdx]) lanHosts(lan).splice(hostIdx, 1);
  renderTopo();
}

function findServerLocation(ip) {
  // Returns "R1 Fa0/0 · 192.168.1.0/24" for an attached server IP, else null
  for(const l of topo.lans) {
    if(lanHosts(l).find(h=>h.kind==='server'&&h.ip===ip)) return `${l.router} ${l.iface} · ${l.network}`;
  }
  return null;
}
function editLink(idx) {
  const l = topo.links[idx];
  if(!l) return;
  showModal('Edit WAN Link', [
    {type:'row', fields:[{key:'ipA', label:l.a.router+' '+l.a.iface+' IP', value:l.a.ip}, {key:'ipB', label:l.b.router+' '+l.b.iface+' IP', value:l.b.ip}]},
    {type:'row', fields:[{key:'network', label:'Network/CIDR', value:l.network}, {key:'dce', label:'DCE Side (a/b)', value:l.a.dce?'a':'b'}]},
  ], {type:'link', idx});
}
function editLAN(idx) {
  const l = topo.lans[idx];
  if(!l) return;
  // Hosts are managed on the LAN card (× to remove, Devices section to add)
  showModal('Edit LAN: '+l.network, [
    {type:'row', fields:[{key:'routerIP', label:'Router IP', value:l.routerIP}, {key:'network', label:'Network/CIDR', value:l.network}]},
  ], {type:'lan', idx});
}
function reassignLanRouter(idx, newRouter) {
  const lan = topo.lans[idx];
  if(!lan) return;
  // Find first unused Fa interface on new router
  const used = topo.interfaces.filter(i=>i.router===newRouter).map(i=>i.name);
  let iface = 'Fa0/0';
  for(let i=0;i<10;i++){const t='Fa0/'+i;if(!used.includes(t)){iface=t;break;}}
  // Remove old interface if it existed
  topo.interfaces = topo.interfaces.filter(i=>!(i.router===lan.router&&i.name===lan.iface));
  // Create new interface
  updateOrCreateIface(newRouter, iface, 'LAN', lan.routerIP, lan.mask, lan.network);
  lan.router = newRouter;
  lan.iface = iface;
  renderTopo();
}

function renderTopo() {
  // Router list
  const rl = document.getElementById('router-list');
  rl.innerHTML = topo.routers.map(r=>`<div class="topo-card"><strong>${r.name}</strong> <button class="remove-btn" onclick="removeRouter('${r.name}')">&times;</button></div>`).join('');

  // Interface list
  const il = document.getElementById('iface-list');
  il.innerHTML = topo.interfaces.map(i=>`<div class="topo-card" style="padding:8px 12px;display:flex;justify-content:space-between;align-items:center">
    <span>
      <strong>${i.router}</strong> ${i.name}
      <span class="tag ${i.type==='LAN'?'tag-green':'tag-purple'}">${i.type}</span>
      <span class="mono" id="iface-ip-${i.router}-${i.name.replace(/\//g,'_')}">${i.ip} ${i.mask}</span>
    </span>
    <span>
      <button class="btn btn-sm btn-yellow" onclick="editIface('${i.router}','${i.name}')" style="margin-right:4px">Edit</button>
      <button class="remove-btn" onclick="removeIface('${i.router}','${i.name}')">&times;</button>
    </span>
  </div>`).join('');

  // Links
  const ll = document.getElementById('link-list');
  ll.innerHTML = topo.links.map((l,i)=>`<div class="topo-card" style="padding:8px 12px;display:flex;justify-content:space-between;align-items:center">
    <span>
      <strong>${l.a.router}</strong> ${l.a.iface} <span class="mono">${l.a.ip}</span> <span class="tag ${l.a.dce?'tag-purple':'tag-blue'}">${l.a.dce?'DCE':'DTE'}</span>
      ↔
      <strong>${l.b.router}</strong> ${l.b.iface} <span class="mono">${l.b.ip}</span> <span class="tag ${l.b.dce?'tag-purple':'tag-blue'}">${l.b.dce?'DCE':'DTE'}</span>
      <span class="tag tag-yellow">${l.network}</span>
    </span>
    <span>
      <button class="btn btn-sm btn-yellow" onclick="editLink(${i})" style="margin-right:4px">Edit</button>
      <button class="remove-btn" onclick="removeLink(${i})">&times;</button>
    </span>
  </div>`).join('');

  // LANs (each LAN owns its router iface + hosts: PCs and servers)
  const lanl = document.getElementById('lan-list');
  lanl.innerHTML = topo.lans.map((l,i)=>{
    const opts = topo.routers.map(r=>`<option${r.name===l.router?' selected':''}>${r.name}</option>`).join('');
    const hostChips = lanHosts(l).map((h,hi)=>{
      const chip = h.kind === 'server'
        ? `<span class="tag tag-purple" title="${h.sub} Server · ${h.ip}">${h.name} <span class="mono">${h.ip}</span></span>`
        : `<span class="tag tag-green" title="PC · ${h.ip}">${h.name} <span class="mono">${h.ip}</span></span>`;
      return `${chip} <button class="remove-btn" onclick="removeHostFromLAN(${i},${hi})" title="Remove ${h.name}">&times;</button>`;
    }).join(' ');
    return `<div class="topo-card" style="padding:8px 12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px">
    <span>
      <select class="vlsm-net-sel" onchange="reassignLanRouter(${i},this.value)" style="margin-right:6px">${opts}</select>
      ${l.iface} <span class="mono">${l.routerIP}</span>
      →
      ${hostChips || '<span style="color:var(--text2)">no hosts</span>'}
      <span class="tag tag-yellow">${l.network}</span>
    </span>
    <span>
      <button class="btn btn-sm btn-yellow" onclick="editLAN(${i})" style="margin-right:4px">Edit</button>
      <button class="remove-btn" onclick="removeLAN(${i})">&times;</button>
    </span>
  </div>`;
  }).join('');

  // Update dropdowns
  const rOpts = topo.routers.map(r=>`<option>${r.name}</option>`).join('');
  document.getElementById('iface-router').innerHTML = rOpts;
  document.getElementById('link-a-router').innerHTML = rOpts;
  document.getElementById('link-b-router').innerHTML = rOpts;
  document.getElementById('lan-router').innerHTML = rOpts;
  updateLinkIfaces('a');
  updateLinkIfaces('b');
  updateLanIfaces();

  // Update new Topology sub-sections
  if(typeof renderIPDelegList === 'function') renderIPDelegList();
  if(typeof refreshPingSelects === 'function') refreshPingSelects();
  if(typeof refreshDevLanSelect === 'function') refreshDevLanSelect();
}

function updateLinkIfaces(side) {
  const router = document.getElementById('link-'+side+'-router').value;
  const ifaces = topo.interfaces.filter(i=>i.router===router);
  document.getElementById('link-'+side+'-iface').innerHTML = ifaces.map(i=>`<option>${i.name}</option>`).join('');
}
function updateLanIfaces() {
  const router = document.getElementById('lan-router').value;
  const ifaces = topo.interfaces.filter(i=>i.router===router&&i.type==='LAN');
  document.getElementById('lan-iface').innerHTML = ifaces.map(i=>`<option>${i.name}</option>`).join('');
}

function clearTopology() {
  if(!confirm('Clear entire topology?')) return;
  topo = {routers:[],interfaces:[],links:[],lans:[]};
  renderTopo();
}

// ============================================================
// LOAD SCENARIO 2
// ============================================================
function loadScenario2() {
  topo = {routers:[],interfaces:[],links:[],lans:[]};

  // Routers
  topo.routers.push({name:'BRANCH'},{name:'HQ'},{name:'ISP'});

  // BRANCH interfaces
  topo.interfaces.push(
    {router:'BRANCH',name:'Fa0/0',type:'LAN',ip:'192.168.1.1',mask:'255.255.255.0',network:'192.168.1.0/24'},
    {router:'BRANCH',name:'S0/0/0',type:'WAN',ip:'10.45.1.2',mask:'255.255.255.0',network:'10.45.1.0/24'}
  );

  // HQ interfaces
  topo.interfaces.push(
    {router:'HQ',name:'Fa0/0',type:'LAN',ip:'10.45.2.1',mask:'255.255.255.0',network:'10.45.2.0/24'},
    {router:'HQ',name:'S0/0/0',type:'WAN',ip:'10.45.1.1',mask:'255.255.255.0',network:'10.45.1.0/24'},
    {router:'HQ',name:'S0/0/1',type:'WAN',ip:'172.20.20.1',mask:'255.255.255.0',network:'172.20.20.0/24'}
  );

  // ISP interfaces
  topo.interfaces.push(
    {router:'ISP',name:'Fa0/0',type:'LAN',ip:'172.16.1.1',mask:'255.255.255.0',network:'172.16.1.0/24'},
    {router:'ISP',name:'S0/0/1',type:'WAN',ip:'172.20.20.2',mask:'255.255.255.0',network:'172.20.20.0/24'}
  );

  // WAN links
  topo.links.push(
    {a:{router:'BRANCH',iface:'S0/0/0',ip:'10.45.1.2',dce:false},b:{router:'HQ',iface:'S0/0/0',ip:'10.45.1.1',dce:true},network:'10.45.1.0/24'},
    {a:{router:'HQ',iface:'S0/0/1',ip:'172.20.20.1',dce:true},b:{router:'ISP',iface:'S0/0/1',ip:'172.20.20.2',dce:false},network:'172.20.20.0/24'}
  );

  // LANs
  topo.lans.push(
    {router:'BRANCH',iface:'Fa0/0',network:'192.168.1.0/24',routerIP:'192.168.1.1',mask:'255.255.255.0',hosts:[{name:'PC1',kind:'pc',ip:'192.168.1.10'}]},
    {router:'HQ',iface:'Fa0/0',network:'10.45.2.0/24',routerIP:'10.45.2.1',mask:'255.255.255.0',hosts:[{name:'PC2',kind:'pc',ip:'10.45.2.10'}]},
    {router:'ISP',iface:'Fa0/0',network:'172.16.1.0/24',routerIP:'172.16.1.1',mask:'255.255.255.0',hosts:[{name:'PC3',kind:'pc',ip:'172.16.1.10'}]}
  );

  renderTopo();
}

// ============================================================
// ROUTING ENGINE
// ============================================================
function toggleStaticRoutes(routerName) {
  const sel = document.getElementById('proto-'+routerName);
  const row = document.getElementById('staticroutes-row-'+routerName);
  const cb = document.getElementById('staticroutes-'+routerName);
  const manualRow = document.getElementById('manualroutes-row-'+routerName);
  if(!sel || !row) return;
  const isStatic = sel.value === 'static';
  row.style.display = isStatic ? 'none' : 'flex';
  if(isStatic) cb.checked = false;
  if(manualRow) manualRow.style.display = isStatic ? 'none' : 'block';
}

function generateRoutes() {
  if(topo.routers.length===0) return alert('Build a topology first');
  if(topo.links.length===0) return alert('Add at least one WAN link');

  // Collect all networks
  const allNetworks = new Set();
  topo.interfaces.forEach(i=>{ if(i.network) allNetworks.add(i.network); });
  topo.lans.forEach(l=>allNetworks.add(l.network));

  // Build per-router connected networks
  const routerNets = {};
  topo.routers.forEach(r=>{ routerNets[r.name] = new Set(); });
  topo.interfaces.forEach(i=>{ if(i.network&&routerNets[i.router]) routerNets[i.router].add(i.network); });
  topo.lans.forEach(l=>{ if(routerNets[l.router]) routerNets[l.router].add(l.network); });

  // Build adjacency: which router connects to which via WAN
  const adjacency = {};
  topo.routers.forEach(r=>{ adjacency[r.name] = new Set(); });
  topo.links.forEach(l=>{
    adjacency[l.a.router].add(l.b.router);
    adjacency[l.b.router].add(l.a.router);
  });

  // Protocol selects — preserve existing selections
  const protoDiv = document.getElementById('route-protocol-selects');
  const savedProtos = {};
  const savedDef = {};
  const savedStatic = {};
  const savedManual = {};
  topo.routers.forEach(r=>{
    const sel = document.getElementById('proto-'+r.name);
    if(sel) savedProtos[r.name] = sel.value;
    const def = document.getElementById('defroute-'+r.name);
    if(def) savedDef[r.name] = def.checked;
    const st = document.getElementById('staticroutes-'+r.name);
    if(st) savedStatic[r.name] = st.checked;
    const mt = document.getElementById('manualroutes-'+r.name);
    if(mt) savedManual[r.name] = mt.value;
  });
  protoDiv.innerHTML = '<div class="grid grid-3">' + topo.routers.map(r=>`
    <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px">
      <label style="font-weight:600;color:var(--accent2)">${r.name}</label>
      <select id="proto-${r.name}" style="margin-top:6px" onchange="toggleStaticRoutes('${r.name}')">
        <option value="static">Static Only</option>
        <option value="ospf">OSPF</option>
        <option value="eigrp">EIGRP</option>
        <option value="ripv1">RIPv1</option>
        <option value="ripv2">RIPv2</option>
      </select>
      <label style="margin-top:8px;display:flex;align-items:center;gap:6px;cursor:pointer;font-size:.85rem">
        <input type="checkbox" id="defroute-${r.name}"> Advertise Default Route
      </label>
      <label id="staticroutes-row-${r.name}" style="margin-top:4px;display:none;align-items:center;gap:6px;cursor:pointer;font-size:.85rem">
        <input type="checkbox" id="staticroutes-${r.name}"> Include Static Routes
      </label>
      <div id="manualroutes-row-${r.name}" style="margin-top:8px;display:none">
        <label style="font-size:.8rem;color:var(--text2)">Manual Routes (one per line)</label>
        <textarea id="manualroutes-${r.name}" rows="3" placeholder="ip route 192.168.100.0 255.255.255.0 172.16.10.2" style="margin-top:4px;width:100%;padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:6px;font-family:monospace;font-size:.8rem;resize:vertical"></textarea>
      </div>
    </div>`).join('') + '</div>';
  // Restore saved selections
  topo.routers.forEach(r=>{
    if(savedProtos[r.name]) document.getElementById('proto-'+r.name).value = savedProtos[r.name];
    if(savedDef[r.name]) document.getElementById('defroute-'+r.name).checked = true;
    if(savedStatic[r.name]) document.getElementById('staticroutes-'+r.name).checked = true;
    if(savedManual[r.name]) document.getElementById('manualroutes-'+r.name).value = savedManual[r.name];
    toggleStaticRoutes(r.name);
  });

  // Generate routes for each router
  const routeTables = {};
  const allNetsArr = [...allNetworks];

  // Pass 1: compute connected + direct neighbor routes for all routers
  topo.routers.forEach(r => {
    const proto = document.getElementById('proto-'+r.name)?.value || 'static';
    const connected = routerNets[r.name];
    const routes = [];
    const knownNets = new Set(connected);

    connected.forEach(net => {
      routes.push({dest:net, mask:maskFromNetwork(net), nextHop:'—', iface:'direct', type:'Connected', proto:'—'});
    });

    const unknownNets = allNetsArr.filter(net => {
      if(connected.has(net)) return false;
      // Skip WAN link networks where this router isn't an endpoint
      for(const l of topo.links) {
        if(l.network === net && l.a.router !== r.name && l.b.router !== r.name) return false;
      }
      return true;
    });
    const netNextHops = {};

    unknownNets.forEach(net => {
      let nextHop = null;
      let outIface = null;

      topo.links.forEach(l => {
        if(l.a.router===r.name && routerNets[l.b.router]?.has(net)) {
          nextHop = l.b.ip; outIface = l.a.iface;
        }
        if(l.b.router===r.name && routerNets[l.a.router]?.has(net)) {
          nextHop = l.a.ip; outIface = l.b.iface;
        }
      });

      if(!nextHop) {
        for(const adj of adjacency[r.name]) {
          if(routerNets[adj]?.has(net)) {
            const link = topo.links.find(l =>
              (l.a.router===r.name&&l.b.router===adj)||(l.b.router===r.name&&l.a.router===adj)
            );
            if(link) {
              nextHop = link.a.router===adj ? link.a.ip : link.b.ip;
              outIface = link.a.router===r.name ? link.a.iface : link.b.iface;
            }
            if(nextHop) break;
          }
        }
      }

      if(nextHop) { netNextHops[net] = {nextHop, outIface}; knownNets.add(net); }
    });

    routeTables[r.name] = {proto, routes, knownNets, netNextHops, unknownNets};
  });

  // Pass 2+: propagate learned routes (up to 5 passes for deep chains)
  for(let pass=0; pass<5; pass++) {
    let changed = false;
    topo.routers.forEach(r => {
      const rt = routeTables[r.name];
      rt.unknownNets.forEach(net => {
        if(rt.knownNets.has(net)) return;
        for(const adj of adjacency[r.name]) {
          if(routeTables[adj]?.knownNets?.has(net)) {
            const link = topo.links.find(l =>
              (l.a.router===r.name&&l.b.router===adj)||(l.b.router===r.name&&l.a.router===adj)
            );
            if(link) {
              rt.netNextHops[net] = {nextHop: link.a.router===adj ? link.a.ip : link.b.ip, outIface: link.a.router===r.name ? link.a.iface : link.b.iface};
              rt.knownNets.add(net);
              changed = true;
            }
            break;
          }
        }
      });
    });
    if(!changed) break;
  }

  // Recompute next hops for newly learned networks
  topo.routers.forEach(r => {
    const rt = routeTables[r.name];
    rt.unknownNets.forEach(net => {
      if(rt.netNextHops[net]) return; // already has next hop
      if(!rt.knownNets.has(net)) return; // not known
      // Find next hop via adjacency (using propagated knowledge)
      for(const adj of adjacency[r.name]) {
        if(routeTables[adj]?.knownNets?.has(net)) {
          const link = topo.links.find(l =>
            (l.a.router===r.name&&l.b.router===adj)||(l.b.router===r.name&&l.a.router===adj)
          );
          if(link) {
            rt.netNextHops[net] = {nextHop: link.a.router===adj ? link.a.ip : link.b.ip, outIface: link.a.router===r.name ? link.a.iface : link.b.iface};
          }
          break;
        }
      }
    });
  });

  // Final: build route entries using propagated knowledge
  topo.routers.forEach(r => {
    const rt = routeTables[r.name];
    const {proto, unknownNets, netNextHops} = rt;

    if(proto === 'static') {
      const wanNeighbors = adjacency[r.name];
      if(wanNeighbors && wanNeighbors.size === 1) {
        const adj = [...wanNeighbors][0];
        const link = topo.links.find(l =>
          (l.a.router===r.name&&l.b.router===adj)||(l.b.router===r.name&&l.a.router===adj)
        );
        if(link) {
          const stubNextHop = link.a.router===adj ? link.a.ip : link.b.ip;
          const stubIface = link.a.router===r.name ? link.a.iface : link.b.iface;
          // Use neighbor's full knownNets (connected + learned) for route decisions
          const adjKnown = routeTables[adj]?.knownNets;
          if(adjKnown) {
            unknownNets.forEach(net => {
              if(adjKnown.has(net)) {
                rt.routes.push({dest:net.split('/')[0], mask:maskFromNetwork(net), nextHop:stubNextHop, iface:stubIface, type:isClassful(net)?'Classful':'Subnet', proto:'Static'});
              }
            });
            const unknownByNeighbor = unknownNets.filter(net => !adjKnown.has(net));
            if(unknownByNeighbor.length > 0) {
              rt.routes.push({dest:'0.0.0.0', mask:'0.0.0.0', nextHop:stubNextHop, iface:stubIface, type:'Default', proto:'Static'});
            }
          }
        }
      } else {
        unknownNets.forEach(net => {
          const nh = netNextHops[net];
          if(nh) rt.routes.push({dest:net.split('/')[0], mask:maskFromNetwork(net), nextHop:nh.nextHop, iface:nh.outIface, type:isClassful(net)?'Classful':'Subnet', proto:'Static'});
        });
      }
    } else {
      unknownNets.forEach(net => {
        const nh = netNextHops[net];
        if(nh) rt.routes.push({dest:net.split('/')[0], mask:maskFromNetwork(net), nextHop:nh.nextHop, iface:nh.outIface, type:isClassful(net)?'Classful':'Subnet', proto:proto.toUpperCase()});
      });
    }
  });

  // Add default route for routers advertising default
  topo.routers.forEach(r => {
    const advertiseDef = document.getElementById('defroute-'+r.name)?.checked;
    if(!advertiseDef) return;
    const rt = routeTables[r.name];
    // Find WAN next-hop (first WAN link neighbor)
    const wanLinks = topo.links.filter(l=>l.a.router===r.name||l.b.router===r.name);
    if(wanLinks.length > 0) {
      const l = wanLinks[0];
      const nextHop = l.a.router===r.name ? l.b.ip : l.a.ip;
      const iface = l.a.router===r.name ? l.a.iface : l.b.iface;
      rt.routes.push({dest:'0.0.0.0', mask:'0.0.0.0', nextHop, iface, type:'Default', proto:rt.proto.toUpperCase()||'Static'});
    }
  });

  // Render
  const tablesDiv = document.getElementById('route-tables');
  tablesDiv.innerHTML = '';
  topo.routers.forEach(r=>{
    const {proto, routes} = routeTables[r.name];
    const div = document.createElement('div');
    div.className = 'result-box';
    div.innerHTML = `<h3 class="rb-title">${r.name} <span class="tag tag-blue">${proto.toUpperCase()}</span></h3>
      <table><thead><tr><th>Destination</th><th>Mask</th><th>Next Hop</th><th>Interface</th><th>Type</th><th>Protocol</th></tr></thead>
      <tbody>${routes.map(rt=>`<tr><td class="mono">${rt.dest}</td><td class="mono">${rt.mask}</td><td class="mono">${rt.nextHop}</td><td>${rt.iface}</td><td><span class="tag tag-green">${rt.type}</span></td><td>${rt.proto}</td></tr>`).join('')}</tbody></table>`;
    tablesDiv.appendChild(div);
  });

  window._routeTables = routeTables;
  window._allNetworks = allNetworks;
  window._routerNets = routerNets;
}

function maskFromNetwork(net) {
  const cidr = parseInt(net.split('/')[1])||24;
  return IP.toString(IP.maskFromCIDR(cidr));
}

function isClassful(net) {
  const cidr = parseInt(net.split('/')[1]);
  const first = parseInt(net.split('.')[0]);
  if(first<128) return cidr===8;
  if(first<192) return cidr===16;
  return cidr===24;
}

function buildRoutingIOS(r, routeTables) {
  // Routing-protocol + static IOS for one router. Shared by the
  // Routing section output and the full per-router configs.
  const {proto} = routeTables[r.name];
  const ifaces = topo.interfaces.filter(i=>i.router===r.name);
  let cfg = '';
  // Routing protocol
  const advertiseDef = document.getElementById('defroute-'+r.name)?.checked;
  if(proto==='ripv1' || proto==='ripv2') {
    cfg += `router rip\n`;
    if(proto==='ripv2') cfg += ` version 2\n`;
    const nets = window._routerNets[r.name];
    const advertised = new Set();
    nets.forEach(net=>{
      const classful = toClassful(net);
      if(!advertised.has(classful)) {
        cfg += ` network ${classful}\n`;
        advertised.add(classful);
      }
    });
    ifaces.filter(i=>i.type==='LAN').forEach(i=>{
      cfg += ` passive-interface ${i.name}\n`;
    });
    if(proto==='ripv2') cfg += ` no auto-summary\n`;
    if(advertiseDef) cfg += ` default-information originate\n`;
  } else if(proto==='ospf') {
    cfg += `router ospf 1\n`;
    const nets = window._routerNets[r.name];
    nets.forEach(net=>{
      const cidr = parseInt(net.split('/')[1])||24;
      const wildcard = IP.wildcardFromMask(IP.toString(IP.maskFromCIDR(cidr)));
      cfg += ` network ${net.split('/')[0]} ${wildcard} area 0\n`;
    });
    ifaces.filter(i=>i.type==='LAN').forEach(i=>{
      cfg += ` passive-interface ${i.name}\n`;
    });
    if(advertiseDef) cfg += ` default-information originate\n`;
  } else if(proto==='eigrp') {
    cfg += `router eigrp 100\n`;
    const nets = window._routerNets[r.name];
    nets.forEach(net=>{
      const cidr = parseInt(net.split('/')[1])||24;
      const wildcard = IP.wildcardFromMask(IP.toString(IP.maskFromCIDR(cidr)));
      cfg += ` network ${net.split('/')[0]} ${wildcard}\n`;
    });
    ifaces.filter(i=>i.type==='LAN').forEach(i=>{
      cfg += ` passive-interface ${i.name}\n`;
    });
    if(advertiseDef) cfg += ` redistribute static\n`;
  }

  // Static routes — for static protocol OR when "Include Static Routes" is checked with dynamic protocol
  const includeStatic = document.getElementById('staticroutes-'+r.name)?.checked;
  if(proto === 'static' || includeStatic) {
    const staticRoutes = routeTables[r.name].routes.filter(rt=>rt.type!=='Connected'&&rt.type!=='Classful');
    const seenRoutes = new Set();
    staticRoutes.forEach(rt=>{
      const key = rt.dest+'/'+rt.mask+'/'+rt.nextHop;
      if(seenRoutes.has(key)) return;
      seenRoutes.add(key);
      cfg += `ip route ${rt.dest} ${rt.mask} ${rt.nextHop}\n`;
    });
  }

  // Manual routes — user-typed extra static routes
  const manualText = document.getElementById('manualroutes-'+r.name)?.value?.trim();
  if(manualText) {
    manualText.split('\n').forEach(line=>{
      const trimmed = line.trim();
      if(trimmed && trimmed.startsWith('ip route')) {
        cfg += trimmed + '\n';
      }
    });
  }

  // Default static route for advertising routers
  if(advertiseDef && proto !== 'static') {
    const wanLinks = topo.links.filter(l=>l.a.router===r.name||l.b.router===r.name);
    if(wanLinks.length > 0) {
      const wl = wanLinks[0];
      const defNextHop = wl.a.router===r.name ? wl.b.ip : wl.a.ip;
      cfg += `!\nip route 0.0.0.0 0.0.0.0 ${defNextHop}\n`;
    }
  }
  return cfg;
}

function generateRoutingIOS() {
  // Terminal output for the Routing section: per-router routing IOS only.
  const output = document.getElementById('routing-ios-output');
  if(!output) return;
  if(!window._routeTables) {
    output.innerHTML = '<div class="result-box" style="border-color:var(--red)"><p style="color:var(--red)">Build Routing Tables first.</p></div>';
    return;
  }
  const routeTables = window._routeTables;
  let html = '';
  topo.routers.forEach(r=>{
    const {proto} = routeTables[r.name];
    let cfg = buildRoutingIOS(r, routeTables);
    if(!cfg.trim()) cfg = '! No routing commands — all networks directly connected.\n';
    html += `<div class="result-box"><h3 class="rb-title">${r.name} <span class="tag tag-blue">${proto.toUpperCase()}</span> <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3><pre class="mono">${cfg}</pre></div>`;
  });
  output.innerHTML = html;
}

// ============================================================
// CONFIG GENERATOR
// ============================================================
function generateConfigs() {
  if(topo.routers.length === 0) {
    document.getElementById('config-output').innerHTML = '<div class="result-box" style="border-color:var(--red)"><p style="color:var(--red)">No topology yet. Build a topology first, then build routing tables.</p></div>';
    return;
  }
  if(!window._routeTables) { generateRoutes(); }
  if(!window._routeTables) {
    document.getElementById('config-output').innerHTML = '<div class="result-box" style="border-color:var(--red)"><p style="color:var(--red)">Routing tables not built. Add at least one WAN link, then click "Build Routing Tables".</p></div>';
    return;
  }

  // Pre-flight: check for missing IPs
  const missingIps = topo.interfaces.filter(i => !i.ip);
  if(missingIps.length > 0) {
    const list = missingIps.map(i => `${i.router} ${i.name}`).join(', ');
    document.getElementById('config-output').innerHTML = `<div class="result-box" style="border-color:var(--yellow)"><p style="color:var(--yellow)"><strong>Warning:</strong> ${missingIps.length} interface(s) missing IP: ${list}. Config will skip these.</p></div>`;
  }

  const routeTables = window._routeTables;
  const output = document.getElementById('config-output');
  output.innerHTML = '';

  const usePasswords = document.getElementById('use-passwords').checked;
  const enablePass = document.getElementById('global-enable-pass').value || 'class';
  const linePass = document.getElementById('global-line-pass').value || 'cisco';
  const bannerText = document.getElementById('global-banner').value || '';

  topo.routers.forEach(r=>{
    const {proto} = routeTables[r.name];
    const ifaces = topo.interfaces.filter(i=>i.router===r.name);
    const lans = topo.lans.filter(l=>l.router===r.name);
    const links = topo.links.filter(l=>l.a.router===r.name||l.b.router===r.name);

    let cfg = `hostname ${r.name}\n`;
    if(usePasswords) {
      cfg += `enable secret ${enablePass}\n!\nline console 0\n password ${linePass}\n login\nline vty 0 4\n password ${linePass}\n login\n!\n`;
    }

    // Interfaces
    ifaces.forEach(i=>{
      cfg += `interface ${i.name}\n`;
      if(i.ip && i.mask) {
        cfg += ` ip address ${i.ip} ${i.mask}\n`;
      } else {
        cfg += `! ip address (missing — configure manually)\n`;
      }
      if(i.type==='WAN') {
        const link = links.find(l=>(l.a.router===r.name&&l.a.iface===i.name)||(l.b.router===r.name&&l.b.iface===i.name));
        if(link && ((link.a.router===r.name&&link.a.dce)||(link.b.router===r.name&&link.b.dce))) {
          cfg += ` clock rate 64000\n`;
        }
      }
      cfg += ` no shutdown\n!\n`;
    });

    // Routing protocol + static routes (shared builder — also used by the Routing section)
    cfg += buildRoutingIOS(r, routeTables);

    cfg += `!\nbanner motd #${bannerText || r.name + ' Router'}#`;

    const div = document.createElement('div');
    div.className = 'result-box';
    div.innerHTML = `<h3 class="rb-title">${r.name} <span class="tag tag-blue">${proto.toUpperCase()}</span> <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3>
      <pre class="mono">${cfg}</pre>`;
    output.appendChild(div);
  });
}

function toClassful(net) {
  const first = parseInt(net.split('.')[0]);
  if(first<128) return net.split('.')[0]+'.0.0.0';
  if(first<192) return net.split('.')[0]+'.'+net.split('.')[1]+'.0.0';
  return net.split('.')[0]+'.'+net.split('.')[1]+'.'+net.split('.')[2]+'.0';
}

function copyConfig(btn) {
  const pre = btn.closest('.result-box').querySelector('pre');
  navigator.clipboard.writeText(pre.textContent).then(()=>{
    btn.textContent = 'Copied!';
    setTimeout(()=>btn.textContent='Copy',2000);
  });
}

// ============================================================
// MODAL EDITOR
// ============================================================
let _modalCtx = null; // {type, router, name, idx}

function showModal(title, fields, ctx) {
  _modalCtx = ctx;
  document.getElementById('modal-title').textContent = title;
  const container = document.getElementById('modal-fields');
  container.innerHTML = fields.map(f => {
    if(f.type === 'row') {
      return `<div class="modal-row">${f.fields.map(sf => `<div><label>${sf.label}</label><input type="text" id="mf-${sf.key}" value="${sf.value||''}" style="width:100%;padding:8px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:6px;font-family:monospace"></div>`).join('')}</div>`;
    }
    return `<div class="modal-row full"><div><label>${f.label}</label><input type="text" id="mf-${f.key}" value="${f.value||''}" style="width:100%;padding:8px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:6px;font-family:monospace"></div></div>`;
  }).join('');
  document.getElementById('topo-modal').style.display = 'flex';
}

function closeModal() {
  document.getElementById('topo-modal').style.display = 'none';
  _modalCtx = null;
}

function saveModal() {
  if(!_modalCtx) return;
  const v = key => document.getElementById('mf-'+key)?.value || '';
  const ctx = _modalCtx;

  if(ctx.type === 'iface') {
    const iface = topo.interfaces.find(i=>i.router===ctx.router&&i.name===ctx.name);
    if(iface) {
      const newIP = v('ip');
      const newMask = v('mask');
      if(newIP) {
        iface.ip = newIP;
        iface.mask = newMask || iface.mask;
        topo.links.forEach(l=>{
          if(l.a.router===ctx.router&&l.a.iface===ctx.name) l.a.ip = newIP;
          if(l.b.router===ctx.router&&l.b.iface===ctx.name) l.b.ip = newIP;
        });
        topo.lans.forEach(l=>{
          if(l.router===ctx.router&&l.iface===ctx.name) l.routerIP = newIP;
        });
      }
    }
  } else if(ctx.type === 'link') {
    const link = topo.links[ctx.idx];
    if(link) {
      const newIpA = v('ipA');
      const newIpB = v('ipB');
      const newNetwork = v('network');
      const newDce = v('dce');
      if(newIpA) {
        link.a.ip = newIpA;
        const ifaceA = topo.interfaces.find(i=>i.router===link.a.router&&i.name===link.a.iface);
        if(ifaceA) ifaceA.ip = newIpA;
      }
      if(newIpB) {
        link.b.ip = newIpB;
        const ifaceB = topo.interfaces.find(i=>i.router===link.b.router&&i.name===link.b.iface);
        if(ifaceB) ifaceB.ip = newIpB;
      }
      if(newNetwork) link.network = newNetwork;
      if(newDce) {
        link.a.dce = newDce === 'a';
        link.b.dce = newDce === 'b';
      }
    }
  } else if(ctx.type === 'lan') {
    const lan = topo.lans[ctx.idx];
    if(lan) {
      const newRouterIP = v('routerIP');
      const newNetwork = v('network');
      const newRouter = v('router');
      const newIface = v('iface');
      if(newRouterIP) {
        lan.routerIP = newRouterIP;
        const iface = topo.interfaces.find(i=>i.router===lan.router&&i.name===lan.iface);
        if(iface) iface.ip = newRouterIP;
      }
      if(newNetwork) lan.network = newNetwork;
      if(newRouter && newRouter !== lan.router) {
        reassignLanRouter(ctx.idx, newRouter);
        closeModal();
        return;
      }
    }
  }
  closeModal();
  renderTopo();
}

// ============================================================
// ADDRESSING TABLE
// ============================================================
function generateAddressing() {
  const output = document.getElementById('addressing-output');

  // Mode 1: From topology (if built)
  if(topo.routers.length > 0) {
    let html = '<table><thead><tr><th>Device</th><th>Interface</th><th>IP Address</th><th>Subnet Mask</th><th>Default Gateway</th><th>Switch Port</th><th>VLAN</th><th>Network</th></tr></thead><tbody>';
    topo.interfaces.forEach(i=>{
      const gw = i.type==='LAN' ? i.ip : 'N/A';
      const sp = i.type==='LAN' ? 'Fa0/'+(topo.interfaces.filter(x=>x.router===i.router&&x.type==='LAN').indexOf(i)+1) : 'N/A';
      const lanMatch = topo.lans.find(l=>l.router===i.router&&l.iface===i.name);
      const vlan = i.type==='LAN' ? (lanMatch ? 10+topo.lans.indexOf(lanMatch) : 1) : 'N/A';
      html += `<tr><td><strong>${i.router}</strong></td><td>${i.name}</td><td class="mono">${i.ip}</td><td class="mono">${i.mask}</td><td>${gw}</td><td>${sp}</td><td>${vlan}</td><td class="mono">${i.network}</td></tr>`;
    });
    topo.lans.forEach(l=>{
      // Switch ports numbered sequentially across all hosts in the subnet
      lanHosts(l).forEach((h,hi)=>{
        const label = h.kind === 'server' ? `<strong>${h.name}</strong> <span class="tag tag-purple">${h.sub}</span>` : `<strong>${h.name}</strong>`;
        html += `<tr><td>${label}</td><td>NIC</td><td class="mono">${h.ip}</td><td class="mono">${l.mask}</td><td class="mono">${l.routerIP}</td><td>Fa0/${hi+1}</td><td>${10+topo.lans.indexOf(l)}</td><td class="mono">${l.network}</td></tr>`;
      });
    });
    html += '</tbody></table>';
    output.innerHTML = html;
    return;
  }

  // Mode 2: From VLSM results (topology not yet built)
  if(window._vlsmSubnets && window._vlsmSubnets.length > 0) {
    let html = '<table><thead><tr><th>Name</th><th>Network</th><th>Subnet Mask</th><th>CIDR</th><th>Range</th><th>Broadcast</th><th>Usable</th></tr></thead><tbody>';
    window._vlsmSubnets.forEach(s=>{
      const si = IP.toInt(s.subnet);
      const mask = IP.toString(IP.maskFromCIDR(s.cidr));
      const range = s.cidr === 31
        ? IP.toString(si) + ' - ' + IP.toString((si+1)>>>0)
        : IP.toString((si+1)>>>0) + ' - ' + IP.toString((si+s.block-2)>>>0);
      const bcast = IP.toString((si+s.block-1)>>>0);
      const usable = s.cidr >= 31 ? s.block : s.block - 2;
      html += `<tr><td><strong>${s.name}</strong></td><td class="mono">${s.subnet}/${s.cidr}</td><td class="mono">${mask}</td><td class="mono">/${s.cidr}</td><td class="mono">${range}</td><td class="mono">${bcast}</td><td>${usable}</td></tr>`;
    });
    html += '</tbody></table>';
    html += '<p style="color:var(--text2);font-size:.85rem;margin-top:8px">From VLSM results. Build a topology to see per-device addresses.</p>';
    output.innerHTML = html;
    return;
  }

  output.innerHTML = '<div class="result-box" style="border-color:var(--yellow)"><p style="color:var(--yellow)">No data yet. Calculate VLSM first, or build a topology.</p></div>';
}
function calcNetwork(ip, mask) {
  if(!ip || !mask) return '';
  const ipN = IP.toInt(ip);
  const maskN = IP.toInt(mask);
  return IP.toString((ipN & maskN)>>>0);
}

// ============================================================
// IPv6 ADDRESSING
// ============================================================
function expandIPv6(addr) {
  // Expand :: to full 32 hex chars
  const parts = addr.split('::');
  if(parts.length === 2) {
    const left = parts[0] ? parts[0].split(':').filter(Boolean) : [];
    const right = parts[1] ? parts[1].split(':').filter(Boolean) : [];
    const fillCount = 8 - left.length - right.length;
    const fill = Array(Math.max(0, fillCount)).fill('0');
    return [...left, ...fill, ...right].map(g => g.padStart(4, '0')).join('');
  }
  return addr.split(':').filter(Boolean).map(g => g.padStart(4, '0')).join('').padEnd(32, '0');
}

function ipv6AddPrefix(hex32, addend) {
  let big = BigInt('0x' + hex32);
  big += BigInt(addend);
  const h = big.toString(16).padStart(32, '0');
  return h.match(/.{1,4}/g).join(':');
}

function generateIPv6Subnets() {
  const prefix = document.getElementById('ipv6-prefix').value.trim();
  const prefixLen = parseInt(document.getElementById('ipv6-prefix-len').value);
  const count = parseInt(document.getElementById('ipv6-subnet-count').value) || 8;
  const output = document.getElementById('ipv6-output');
  if(!prefix) return output.innerHTML = '<p style="color:var(--red)">Enter a prefix.</p>';
  const hostBits = 128 - prefixLen;
  const subnetBits = Math.max(1, Math.ceil(Math.log2(count)));
  if(subnetBits > hostBits) return output.innerHTML = '<p style="color:var(--red)">Not enough space for that many subnets.</p>';
  const newPrefixLen = prefixLen + subnetBits;
  const blockSize = Math.pow(2, 128 - newPrefixLen);

  // Expand prefix to 32 hex chars, then take the prefix portion
  const fullHex = expandIPv6(prefix);
  const prefixHex = fullHex.substring(0, prefixLen / 4);

  let table = '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:.85rem"><tr style="background:var(--surface2)"><th style="padding:6px;text-align:left">Subnet #</th><th style="padding:6px;text-align:left">Prefix</th><th style="padding:6px;text-align:left">First Usable</th><th style="padding:6px;text-align:left">Last Usable</th></tr>';
  for(let i = 0; i < count; i++) {
    // Build subnet: prefix hex + subnet index in binary (padded to subnetBits) + host zeros
    const indexHex = i.toString(16).padStart(Math.ceil(subnetBits / 4), '0');
    const remainingZeros = '0'.repeat((128 - prefixLen - subnetBits) / 4);
    const subnetFullHex = (prefixHex + indexHex + remainingZeros).substring(0, 32).padEnd(32, '0');
    const subnetStr = subnetFullHex.match(/.{1,4}/g).join(':');
    const firstUsable = ipv6AddPrefix(subnetFullHex, 1);
    const lastUsable = ipv6AddPrefix(subnetFullHex, blockSize - 2);
    table += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:6px">${i + 1}</td><td style="padding:6px">${subnetStr}/${newPrefixLen}</td><td style="padding:6px">${firstUsable}</td><td style="padding:6px">${lastUsable}</td></tr>`;
  }
  table += '</table>';
  output.innerHTML = table;
}

function generateIPv6LinkLocal() {
  const mac = document.getElementById('ipv6-mac').value.trim();
  const output = document.getElementById('ipv6-linklocal-output');
  if(!mac) return output.innerHTML = '<p style="color:var(--red)">Enter a MAC.</p>';
  const clean = mac.replace(/[:\-\.]/g, '');
  if(clean.length !== 12) return output.innerHTML = '<p style="color:var(--red)">Invalid MAC.</p>';
  const eui = clean.substring(0, 6) + 'FFFE' + clean.substring(6);
  const bytes = eui.match(/.{2}/g).map(b => parseInt(b, 16) ^ 0x02);
  const linkLocal = 'FE80::' + bytes.map(b => b.toString(16).padStart(2, '0')).join('').match(/.{1,4}/g).join(':');
  output.innerHTML = `<div class="result-box"><pre class="mono">Link-Local: ${linkLocal}/64</pre></div>`;
}

// ============================================================
// NAT CONFIGURATION
// ============================================================
function generateNAT() {
  const natType = document.getElementById('nat-type').value;
  const insideIfaces = document.getElementById('nat-inside-ifaces').value.split(',').map(s=>s.trim()).filter(Boolean);
  const outsideIface = document.getElementById('nat-outside-iface').value.trim();
  const poolStart = document.getElementById('nat-pool-start').value.trim();
  const poolEnd = document.getElementById('nat-pool-end').value.trim();
  const poolMask = document.getElementById('nat-pool-mask').value.trim();
  const staticMap = document.getElementById('nat-static-map').value.trim();
  const acl = document.getElementById('nat-acl').value.trim();
  const output = document.getElementById('nat-output');
  if(!outsideIface) return output.innerHTML = '<p style="color:var(--red)">Enter outside interface.</p>';
  let cfg = `! --- NAT Configuration ---\n`;
  insideIfaces.forEach(i => { cfg += `interface ${i}\n ip nat inside\n!\n`; });
  cfg += `interface ${outsideIface}\n ip nat outside\n!\n`;
  if(natType === 'pat') {
    if(acl) cfg += `access-list 1 permit ${acl}\n`;
    cfg += `ip nat inside source list 1 interface ${outsideIface} overload\n`;
  } else if(natType === 'static' && staticMap) {
    const parts = staticMap.split(/\s+/);
    if(parts.length >= 2) cfg += `ip nat inside source static ${parts[0]} ${parts[1]}\n`;
  } else if(natType === 'pool' && poolStart && poolEnd) {
    if(acl) cfg += `access-list 1 permit ${acl}\n`;
    cfg += `ip nat pool MYPOOL ${poolStart} ${poolEnd} netmask ${poolMask || '255.255.255.0'}\n`;
    cfg += `ip nat inside source list 1 pool MYPOOL\n`;
  }
  output.innerHTML = `<div class="result-box"><h3 class="rb-title">NAT Config <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3><pre class="mono">${cfg}</pre></div>`;
}

// ============================================================
// FHRP CONFIGURATION
// ============================================================
function generateFHRP() {
  const proto = document.getElementById('fhrp-proto').value;
  const group = document.getElementById('fhrp-group').value;
  const vip = document.getElementById('fhrp-vip').value.trim();
  const iface = document.getElementById('fhrp-iface').value.trim();
  const pri1 = document.getElementById('fhrp-pri1').value;
  const pri2 = document.getElementById('fhrp-pri2').value;
  const preempt = document.getElementById('fhrp-preempt').value;
  const auth = document.getElementById('fhrp-auth').value.trim();
  const output = document.getElementById('fhrp-output');
  if(!vip || !iface) return output.innerHTML = '<p style="color:var(--red)">Enter virtual IP and interface.</p>';
  const kw = proto === 'hsrp' ? 'standby' : proto === 'vrrp' ? 'vrrp' : 'glbp';
  let r1 = `! --- Router 1 (${proto.toUpperCase()} Active) ---\ninterface ${iface}\n`;
  let r2 = `! --- Router 2 (${proto.toUpperCase()} Standby) ---\ninterface ${iface}\n`;
  if(proto === 'hsrp') {
    r1 += ` standby ${group} ip ${vip}\n standby ${group} priority ${pri1}\n standby ${group} preempt\n`;
    r2 += ` standby ${group} ip ${vip}\n standby ${group} priority ${pri2}\n standby ${group} preempt\n`;
    if(auth) { r1 += ` standby ${group} authentication md5 key-string ${auth}\n`; r2 += ` standby ${group} authentication md5 key-string ${auth}\n`; }
  } else if(proto === 'vrrp') {
    r1 += ` vrrp ${group} ip ${vip}\n vrrp ${group} priority ${pri1}\n vrrp ${group} preempt\n`;
    r2 += ` vrrp ${group} ip ${vip}\n vrrp ${group} priority ${pri2}\n vrrp ${group} preempt\n`;
  } else {
    r1 += ` glbp ${group} ip ${vip}\n glbp ${group} priority ${pri1}\n glbp ${group} preempt\n`;
    r2 += ` glbp ${group} ip ${vip}\n glbp ${group} priority ${pri2}\n glbp ${group} preempt\n`;
  }
  output.innerHTML = `<div class="result-box"><h3 class="rb-title">Router 1 <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3><pre class="mono">${r1}</pre></div><div class="result-box"><h3 class="rb-title">Router 2 <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3><pre class="mono">${r2}</pre></div>`;
}

// ============================================================
// SERVER CONFIGURATION (HTTP / DNS / Email)
// ============================================================
function generateServers() {
  saveSvcForm();
  const output = document.getElementById('servers-output');
  let html = '';

  topo.lans.forEach(l=>{
    lanHosts(l).forEach(h=>{
      if(h.kind !== 'server') return;
      const svc = h.svc || svcDefaults(h.sub, h.name);
      const loc = findServerLocation(h.ip);
      const locLine = loc ? `! Attached: ${loc}\n` : '';

      // HTTP/HTTPS
      if(h.sub === 'HTTP') {
        const port = svc.port || '80';
        const https = svc.https !== false && svc.https !== 'false' && svc.https !== '';
        let cfg = `! --- HTTP${https ? '/HTTPS' : ''} Server (${h.name} · ${h.ip}) ---\n`;
        cfg += locLine;
        cfg += `ip http server\n`;
        cfg += `ip http port ${port}\n`;
        if(https) cfg += `ip http secure-server\n ip https port 443\n crypto pki trustpoint SELF-SIGNED\n  enrollment selfsigned\n!\n crypto key generate rsa modulus 2048\n!\n ip http authentication local\n`;
        cfg += `username admin privilege 15 secret cisco\n`;
        html += `<div class="result-box"><h3 class="rb-title">HTTP/HTTPS — ${h.name} <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3><pre class="mono">${cfg}</pre></div>`;
      }

      // DNS
      if(h.sub === 'DNS' && svc.domain) {
        const records = svc.records || [];
        let ptCfg = `Packet Tracer — Services > DNS (${h.name} · ${h.ip})\n`;
        ptCfg += locLine;
        ptCfg += `  DNS Service: ${svc.enabled === 'off' ? 'Off' : 'On'}\n\n`;
        ptCfg += `  Resource Records:\n`;
        ptCfg += `  ${'No.'.padEnd(5)}${'Name'.padEnd(25)}${'Type'.padEnd(15)}Detail\n`;
        ptCfg += `  ${'-'.repeat(60)}\n`;
        records.forEach((r, i) => {
          ptCfg += `  ${String(i).padEnd(5)}${r.name.padEnd(25)}${r.type.padEnd(15)}${r.val}\n`;
        });

        let iosCfg = `! --- IOS Router DNS (${h.name}) ---\n`;
        iosCfg += `ip domain-lookup\n`;
        iosCfg += `ip name-server ${h.ip}\n`;
        iosCfg += `ip domain-name ${svc.domain}\n!\n`;
        iosCfg += `! Static Host Entries (router DNS)\n`;
        records.filter(r=>r.type==='A Record').forEach(r => {
          iosCfg += `ip host ${r.name} ${r.val}\n`;
        });

        html += `<div class="result-box"><h3 class="rb-title">DNS — ${h.name} · PT GUI <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3><pre class="mono">${ptCfg}</pre></div>`;
        html += `<div class="result-box"><h3 class="rb-title">DNS — ${h.name} · IOS <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3><pre class="mono">${iosCfg}</pre></div>`;
      }

      // Email (SMTP/POP3/IMAP)
      if(h.sub === 'Email' && svc.domain) {
        const smtp = svc.smtp || '25', pop3 = svc.pop3 || '110', imap = svc.imap || '143';
        const smtpState = svc.smtpOn === 'off' ? 'OFF' : 'ON';
        const pop3State = svc.pop3On === 'off' ? 'OFF' : 'ON';
        let cfg = `! --- Email Server ${h.name} (${svc.domain} · ${h.ip}) ---\n`;
        cfg += locLine;
        cfg += `ip domain-name ${svc.domain}\n!\n`;
        cfg += `! PT Walkthrough — Services > EMAIL on ${h.name}:\n`;
        cfg += `!   1. SMTP Service: ${smtpState}   POP3 Service: ${pop3State}\n`;
        cfg += `!   2. Domain Name: ${svc.domain} → Set\n`;
        cfg += `!   SMTP  : ${h.ip}:${smtp}\n`;
        cfg += `!   POP3  : ${h.ip}:${pop3}\n`;
        cfg += `!   IMAP  : ${h.ip}:${imap}\n!\n`;
        const mailUsers = svc.users || [];
        if(mailUsers.length) {
          cfg += `!   3. User Setup (+) — from topology PCs:\n`;
          mailUsers.forEach(u=>{ cfg += `!      + ${u.name} / ${u.pass}\n`; });
          cfg += `!\n`;
        }
        cfg += `! Client Settings:\n`;
        cfg += `!   SMTP Server: ${h.ip}\n`;
        cfg += `!   SMTP Port  : ${smtp}\n`;
        cfg += `!   POP3 Server: ${h.ip}\n`;
        cfg += `!   POP3 Port  : ${pop3}\n`;
        cfg += `!   IMAP Server: ${h.ip}\n`;
        cfg += `!   IMAP Port  : ${imap}\n`;
        cfg += `!   Domain     : ${svc.domain}\n!\n`;
        if(svc.from && svc.to) {
          cfg += `! Test Email:\n`;
          cfg += `!   From: ${svc.from}\n`;
          cfg += `!   To  : ${svc.to}\n`;
          if(svc.subject) cfg += `!   Subj: ${svc.subject}\n`;
          if(svc.body) cfg += `!   Body: ${svc.body}\n`;
        }
        html += `<div class="result-box"><h3 class="rb-title">Email — ${h.name} <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3><pre class="mono">${cfg}</pre></div>`;
      }

      // DHCP server — hosts the pool for its own LAN
      if(h.sub === 'DHCP') {
        const [netPart] = parseNetwork(l.network || '192.168.1.0/24');
        const gw = svc.gw || l.routerIP;
        const mask = svc.mask || l.mask;
        const start = svc.start || incrementIP(netPart, 10);
        const max = svc.max || '50';
        const dns = svc.dns || gw;
        const pool = svc.pool || (h.name.replace(/\s/g,'') + '_pool');
        let cfg = `! --- DHCP Server ${h.name} (${h.ip}) ---\n`;
        cfg += locLine;
        cfg += `Packet Tracer — Services > DHCP\n`;
        cfg += `  Service: On\n  Pool Name: ${pool}\n`;
        cfg += `  Default Gateway: ${gw}\n`;
        cfg += `  Start IP Address: ${start}\n`;
        cfg += `  Subnet Mask: ${mask}\n`;
        cfg += `  Maximum Number of Users: ${max}\n\n`;
        cfg += `ip dhcp excluded-address ${h.ip}\n`;
        cfg += `ip dhcp pool ${pool}\n`;
        cfg += ` network ${calcNetwork(start, mask)} ${mask}\n`;
        cfg += ` default-router ${gw}\n`;
        cfg += ` dns-server ${dns}\n`;
        html += `<div class="result-box"><h3 class="rb-title">DHCP — ${h.name} <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3><pre class="mono">${cfg}</pre></div>`;
      }

      // Generic — static entry only
      if(h.sub === 'Generic') {
        const cfg = `! --- ${h.name} (generic host · ${h.ip}) ---\n${locLine}! Static IP — no service to configure.\n`;
        html += `<div class="result-box"><h3 class="rb-title">${h.name} <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3><pre class="mono">${cfg}</pre></div>`;
      }
    });
  });

  output.innerHTML = html || '<p style="color:var(--text2)">Attach a server in Devices in LAN first.</p>';
}

// ============================================================
// SECURITY (SSH / ACLs)
// ============================================================
function generateSecurity() {
  const hostname = document.getElementById('sec-hostname').value.trim() || 'R1';
  const domain = document.getElementById('sec-domain').value.trim() || 'lab.local';
  const user = document.getElementById('sec-user').value.trim() || 'admin';
  const pass = document.getElementById('sec-pass').value.trim() || 'cisco';
  const rsaBits = document.getElementById('sec-rsa-bits').value;
  const aclType = document.getElementById('sec-acl-type').value;
  const aclNum = document.getElementById('sec-acl-num').value;
  const aclRules = document.getElementById('sec-acl-rules').value.trim().split('\n').filter(l=>l.trim());
  const aclApply = document.getElementById('sec-acl-apply').value;
  const aclIface = document.getElementById('sec-acl-iface').value.trim();
  const output = document.getElementById('security-output');
  let cfg = `! --- SSH Configuration ---\nhostname ${hostname}\nip domain-name ${domain}\nusername ${user} privilege 15 secret ${pass}\ncrypto key generate rsa modulus ${rsaBits}\nip ssh version 2\nline vty 0 4\n transport input ssh\n login local\n!\n`;
  if(aclRules.length > 0) {
    const aclId = aclType === 'standard' ? aclNum : '10' + aclNum;
    cfg += `! --- ACL ${aclId} (${aclType}) ---\n`;
    aclRules.forEach(rule => { cfg += `access-list ${aclId} ${rule}\n`; });
    if(aclIface) cfg += `interface ${aclIface}\n ip access-group ${aclId} ${aclApply}\n`;
  }
  output.innerHTML = `<div class="result-box"><h3 class="rb-title">Security Config <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3><pre class="mono">${cfg}</pre></div>`;
}

// ============================================================
// IP DELEGATION (Static vs DHCP)
// ============================================================
let _ipDelegModes = {}; // deviceKey -> 'static' | 'dhcp'

function renderIPDelegList() {
  const container = document.getElementById('ipdeleg-list');
  if(!container) return;
  const devices = collectDevices();
  if(devices.length === 0) { container.innerHTML = '<p style="color:var(--text2)">Build a topology first.</p>'; return; }

  let html = '<table><thead><tr><th>Device</th><th>IP Address</th><th>Subnet Mask</th><th>Method</th></tr></thead><tbody>';
  devices.forEach((d, i) => {
    const key = d.name;
    const mode = _ipDelegModes[key] || 'static';
    html += `<tr><td><strong>${d.name}</strong> <span class="tag tag-blue">${d.type}</span></td>`;
    html += `<td class="mono">${d.ip}</td><td class="mono">${d.mask}</td>`;
    html += `<td><select data-dev="${key}" onchange="_ipDelegModes[this.dataset.dev]=this.value;renderIPDelegList()">`;
    html += `<option value="static"${mode==='static'?' selected':''}>Static</option>`;
    html += `<option value="dhcp"${mode==='dhcp'?' selected':''}>DHCP</option>`;
    html += `</select></td></tr>`;
  });
  html += '</tbody></table>';
  container.innerHTML = html;
}

function collectDevices() {
  const devices = [];
  // Routers: use first LAN interface IP or first interface IP
  topo.routers.forEach(r => {
    const ifaces = topo.interfaces.filter(i => i.router === r.name);
    const lanIface = ifaces.find(i => i.type === 'LAN');
    const chosen = lanIface || ifaces[0];
    if(chosen && chosen.ip) {
      devices.push({name: r.name, type: 'router', ip: chosen.ip, mask: maskFromNetwork(chosen.network || '0.0.0.0/24'), network: chosen.network || ''});
    } else {
      devices.push({name: r.name, type: 'router', ip: '(no IP)', mask: '—', network: ''});
    }
  });
  // LAN hosts: PCs and attached servers (each belongs to its LAN subnet)
  topo.lans.forEach(l => {
    const cidr = l.network ? (parseInt(l.network.split('/')[1]) || 24) : 24;
    const mask = IP.toString(IP.maskFromCIDR(cidr));
    lanHosts(l).forEach(h => {
      if(!h.ip) return;
      if(h.kind === 'server') {
        devices.push({name: h.name, type: 'server', sub: h.sub, ip: h.ip, mask, network: l.network || ''});
      } else {
        devices.push({name: h.name || 'PC', type: 'pc', ip: h.ip, mask, network: l.network || ''});
      }
    });
  });
  return devices;
}

function findGateway(device) {
  // Find gateway: same network as device, from a router interface
  for(const i of topo.interfaces) {
    if(i.ip === device.ip && i.network === device.network) return i.ip; // self
    if(i.network === device.network && i.ip !== device.ip) return i.ip;
  }
  return null;
}

function incrementIP(ip, n) {
  const parts = ip.split('.').map(Number);
  let val = ((parts[0]<<24)|(parts[1]<<16)|(parts[2]<<8)|parts[3])>>>0;
  val = (val + n)>>>0;
  return [(val>>>24)&255,(val>>>16)&255,(val>>>8)&255,val&255].join('.');
}

function findDhcpServer(device) {
  // DHCP server host on the same network — pools live there, not in delegation.
  if(!device.network) return null;
  for(const l of topo.lans) {
    if(l.network !== device.network) continue;
    const h = lanHosts(l).find(h=>h.kind === 'server' && h.sub === 'DHCP');
    if(h) return {name: h.name, ip: h.ip, pool: (h.svc && h.svc.pool) || (h.name.replace(/\s/g,'') + '_pool')};
  }
  return null;
}

function generateIPDeleg() {
  const output = document.getElementById('ipdeleg-output');
  const devices = collectDevices();
  if(devices.length === 0) { output.innerHTML = '<p style="color:var(--text2)">Build a topology first.</p>'; return; }

  let staticHtml = '', dhcpHtml = '';

  devices.forEach(d => {
    const mode = _ipDelegModes[d.name] || 'static';

    if(mode === 'static') {
      if(d.type === 'router') {
        // Generate interface configs for all interfaces on this router
        topo.interfaces.filter(i => i.router === d.name).forEach(i => {
          if(!i.ip) return;
          const cidr = i.network ? (parseInt(i.network.split('/')[1]) || 24) : 24;
          staticHtml += `interface ${i.name}\n ip address ${i.ip} ${IP.toString(IP.maskFromCIDR(cidr))}\n no shutdown\n!\n`;
        });
        topo.lans.filter(l => l.router === d.name).forEach(l => {
          if(l.routerIP && l.network) {
            const cidr = parseInt(l.network.split('/')[1]) || 24;
            staticHtml += `! LAN on ${d.name}: ${l.routerIP} ${IP.toString(IP.maskFromCIDR(cidr))}\n`;
          }
        });
      } else if(d.type === 'server') {
        const gw = findGateway(d);
        staticHtml += `! ${d.name} (${d.sub || 'Generic'} Server — static):\n`;
        staticHtml += `  IP Address: ${d.ip}\n  Subnet Mask: ${d.mask}\n  Default Gateway: ${gw || '—'}\n`;
      } else {
        const gw = findGateway(d);
        staticHtml += `! ${d.name} (PC):\n`;
        staticHtml += `  IP Address: ${d.ip}\n  Subnet Mask: ${d.mask}\n  Default Gateway: ${gw || '—'}\n`;
      }
    } else {
      // DHCP client — the pool lives on the LAN's DHCP server (Devices in LAN)
      const label = d.type === 'router' ? 'Router' : (d.type === 'server' ? ((d.sub || 'Generic') + ' Server') : 'PC');
      const gw = findGateway(d);
      const srv = findDhcpServer(d);
      dhcpHtml += `! ${d.name} (${label}) — DHCP client:\n`;
      dhcpHtml += `  PT: Desktop > IP Configuration > DHCP\n`;
      if(srv) {
        dhcpHtml += `  Served by: ${srv.name} (${srv.ip}, pool ${srv.pool})\n`;
        if(gw) dhcpHtml += `  Gateway: ${gw}\n`;
      } else {
        dhcpHtml += `  No DHCP server on ${d.network || 'this network'} — attach one in Devices in LAN.\n`;
      }
      dhcpHtml += `!\n`;
    }
  });

  let html = '';
  if(staticHtml) html += `<div class="result-box"><h3 class="rb-title">Static IP Assignments <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3><pre class="mono">${staticHtml}</pre></div>`;
  if(dhcpHtml) html += `<div class="result-box"><h3 class="rb-title">DHCP Clients <button class="btn btn-sm btn-green" onclick="copyConfig(this)">Copy</button></h3><pre class="mono">${dhcpHtml}</pre></div>`;
  output.innerHTML = html || '<p style="color:var(--text2)">No devices to configure.</p>';
}

// ============================================================
// PINGER (Realtime + Simulation diagnosis)
// ============================================================
function refreshPingSelects() {
  const src = document.getElementById('ping-src');
  const dst = document.getElementById('ping-dst');
  if(!src || !dst) return;
  const devices = collectDevices();
  const opts = devices.map(d => `<option value="${d.name}">${d.name} (${d.ip})</option>`).join('');
  const srcVal = src.value, dstVal = dst.value;
  src.innerHTML = opts;
  dst.innerHTML = opts;
  if(srcVal && devices.find(d=>d.name===srcVal)) src.value = srcVal;
  if(dstVal && devices.find(d=>d.name===dstVal)) dst.value = dstVal;
  if(!dstVal && devices.length > 1) dst.selectedIndex = 1;
}

function getDeviceIP(name) {
  const devices = collectDevices();
  const d = devices.find(x => x.name === name);
  return d ? d.ip : null;
}

function findPath(srcName, dstName) {
  // Build adjacency from links
  const adj = {};
  topo.routers.forEach(r => adj[r.name] = new Set());
  topo.links.forEach(l => {
    adj[l.a.router]?.add(l.b.router);
    adj[l.b.router]?.add(l.a.router);
  });

  // Determine which routers the src/dst are behind
  const srcDev = collectDevices().find(d => d.name === srcName);
  const dstDev = collectDevices().find(d => d.name === dstName);
  if(!srcDev || !dstDev) return null;

  // If both on same LAN → direct
  if(srcDev.network && dstDev.network && srcDev.network === dstDev.network) {
    return {hops: [{type:'direct', label: `${srcName} → ${dstName} (same LAN)`}], sameSubnet: true};
  }

  // Find routers
  const srcRouter = srcDev.type === 'router' ? srcDev.name : findDeviceRouter(srcName);
  const dstRouter = dstDev.type === 'router' ? dstDev.name : findDeviceRouter(dstName);

  if(!srcRouter || !dstRouter) return null;

  // BFS shortest path
  const visited = new Set([srcRouter]);
  const queue = [[srcRouter]];
  let path = null;
  while(queue.length > 0) {
    const cur = queue.shift();
    const last = cur[cur.length-1];
    if(last === dstRouter) { path = cur; break; }
    for(const n of (adj[last] || [])) {
      if(!visited.has(n)) {
        visited.add(n);
        queue.push([...cur, n]);
      }
    }
  }
  if(!path) return {hops: [], error: 'No route found — routers are not connected'};

  // Build hop list
  const hops = [];
  if(srcRouter !== srcName) hops.push({type:'local', label: `${srcName} → ${srcRouter}`, iface: findIfaceForDevice(srcName, srcRouter)});

  for(let i = 0; i < path.length - 1; i++) {
    const link = topo.links.find(l =>
      (l.a.router===path[i] && l.b.router===path[i+1]) ||
      (l.b.router===path[i] && l.a.router===path[i+1])
    );
    if(link) {
      const fromIp = link.a.router===path[i] ? link.a.ip : link.b.ip;
      const toIp = link.a.router===path[i+1] ? link.a.ip : link.b.ip;
      const fromIface = link.a.router===path[i] ? link.a.iface : link.b.iface;
      const toIface = link.a.router===path[i+1] ? link.a.iface : link.b.iface;
      hops.push({type:'wan', from: path[i], to: path[i+1], fromIp, toIp, fromIface, toIface, network: link.network});
    }
  }

  if(dstRouter !== dstName) hops.push({type:'local', label: `${dstRouter} → ${dstName}`, iface: findIfaceForDevice(dstName, dstRouter)});

  return {hops, sameSubnet: false, srcRouter, dstRouter};
}

function findDeviceRouter(devName) {
  const l = topo.lans.find(l => lanHosts(l).find(h=>h.name===devName));
  return l ? l.router : null;
}

function findIfaceForDevice(devName, routerName) {
  const l = topo.lans.find(l => lanHosts(l).find(h=>h.name===devName) && l.router === routerName);
  return l ? l.iface : null;
}

function runPing() {
  const src = document.getElementById('ping-src').value;
  const dst = document.getElementById('ping-dst').value;
  const mode = document.getElementById('ping-mode').value;
  const output = document.getElementById('ping-output');
  if(!src || !dst) return;
  if(src === dst) { output.innerHTML = '<div class="result-box" style="border-color:var(--red)"><pre class="mono">Cannot ping to yourself</pre></div>'; return; }

  const path = findPath(src, dst);
  if(!path) { output.innerHTML = '<div class="result-box" style="border-color:var(--red)"><pre class="mono">No path found</pre></div>'; return; }

  if(mode === 'realtime') {
    output.innerHTML = pingRealtime(src, dst, path);
  } else {
    output.innerHTML = pingSimulation(src, dst, path);
  }
}

function pingRealtime(src, dst, path) {
  if(path.error) {
    return `<div class="result-box" style="border-color:var(--red)"><pre class="mono">Type escape sequence to abort.\nSending 5 ICMP Echo requests to ${dst}:\n\n${path.error}\n\nSuccess rate is 0 percent (0/5)</pre></div>`;
  }
  const hopCount = path.hops.length;
  const rttBase = hopCount * 2;
  const success = Math.random() > 0.15;
  const succCount = success ? 5 : (Math.random() > 0.5 ? 4 : 3);
  const marks = '!'.repeat(succCount) + '.'.repeat(5 - succCount);
  const rtts = [];
  for(let i = 0; i < succCount; i++) {
    rtts.push(Math.max(1, rttBase + Math.floor(Math.random() * 4) - 1));
  }

  let out = `Type escape sequence to abort.\n`;
  out += `Sending 5 ICMP Echo requests to ${dst}:\n\n`;
  out += `${marks}\n`;
  out += `\nSuccess rate is ${Math.round(succCount/5*100)} percent (${succCount}/5)\n`;
  if(hopCount > 1 && rtts.length > 0) out += `Round-trip time: ${rtts.join('/')} ms (${hopCount} hops)`;

  return `<div class="result-box" style="border-color:${success?'var(--green)':'var(--yellow)'}"><h3 class="rb-title">Ping ${src} → ${dst} <span class="tag tag-${success?'green':'yellow'}">${success?'SUCCESS':'PARTIAL'}</span></h3><pre class="mono">${out}</pre></div>`;
}

function pingSimulation(src, dst, path) {
  if(path.error) {
    return `<div class="result-box" style="border-color:var(--red)"><h3 class="rb-title">Simulation: ${src} → ${dst} <span class="tag tag-red">FAILED</span></h3><pre class="mono">${path.error}</pre></div>`;
  }

  let out = `=== SIMULATION MODE: ${src} → ${dst} ===\n\n`;
  let failed = false;
  let failReason = '';
  let failHopIndex = -1;

  // Check if routes exist
  if(window._routeTables && Object.keys(window._routeTables).length > 0) {
    for(let i = 0; i < path.hops.length; i++) {
      const hop = path.hops[i];
      if(hop.type === 'wan') {
        const rt = window._routeTables[hop.from];
        if(rt) {
          const dstDev = collectDevices().find(d => d.name === dst);
          if(dstDev && dstDev.network) {
            const hasRoute = rt.knownNets?.has(dstDev.network);
            if(!hasRoute) {
              failed = true;
              failReason = `${hop.from} has no route to ${dstDev.network}`;
              failHopIndex = i;
              break;
            }
          }
        }
      }
    }
  }

  path.hops.forEach((hop, i) => {
    if(hop.type === 'local') {
      out += `[${i+1}] ${hop.label}`;
      out += (failed && i >= failHopIndex) ? ' ✗ UNREACHABLE\n' : ' ✓\n';
    } else if(hop.type === 'wan') {
      out += `[${i+1}] ${hop.from} → ${hop.to} (${hop.network || 'WAN'})\n`;
      out += `     From: ${hop.fromIp} (${hop.fromIface})\n`;
      out += `     To:   ${hop.toIp} (${hop.toIface})\n`;
      if(failed && i >= failHopIndex) {
        out += `     ✗ ${failReason || 'FAILED'}\n`;
      } else {
        out += `     ✓ OK\n`;
      }
    }
  });

  if(!failed) {
    out += `\n=== RESULT: SUCCESS ===\n`;
    out += `All ${path.hops.length} hops reachable. Destination ${dst} responds.\n`;
  } else {
    out += `\n=== RESULT: FAILED ===\n`;
    out += `Diagnosis: ${failReason}\n`;
    out += `Fix: Ensure routing protocol is configured and advertising networks.\n`;
  }

  const color = failed ? 'var(--red)' : 'var(--green)';
  const tag = failed ? 'red' : 'green';
  const status = failed ? 'FAILED' : 'SUCCESS';
  return `<div class="result-box" style="border-color:${color}"><h3 class="rb-title">Simulation: ${src} → ${dst} <span class="tag tag-${tag}">${status}</span></h3><pre class="mono">${out}</pre></div>`;
}

// ============================================================
// OUTPUT TOGGLES — show/hide for every terminal output
// ============================================================
const OUTPUT_TOGGLES = ['flsm-results','vlsm-results','vlsm-ref','addressing-output','ipv6-output',
  'nat-output','fhrp-output','security-output','ipdeleg-output','route-protocol-selects',
  'route-tables','routing-ios-output','ping-output','servers-output','config-output'];

function toggleOutput(id, btn) {
  const el = document.getElementById(id);
  if(!el) return;
  const hidden = el.style.display === 'none';
  el.style.display = hidden ? '' : 'none';
  if(btn) btn.textContent = hidden ? 'Hide' : 'Show';
}

function injectOutputToggles() {
  OUTPUT_TOGGLES.forEach(id=>{
    const el = document.getElementById(id);
    if(!el || el.dataset.toggled) return;
    el.dataset.toggled = '1';
    const btn = document.createElement('button');
    btn.className = 'btn btn-sm';
    btn.style.cssText = 'margin-bottom:6px';
    btn.setAttribute('aria-label', 'Show or hide this output');
    const startHidden = el.style.display === 'none' || el.classList.contains('hidden');
    btn.textContent = startHidden ? 'Show' : 'Hide';
    btn.onclick = () => toggleOutput(id, btn);
    el.parentNode.insertBefore(btn, el);
  });
}

// ============================================================
// INIT
// ============================================================
renderTopo();
renderIPDelegList();
refreshPingSelects();
injectOutputToggles();