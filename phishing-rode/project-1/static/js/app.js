function escapeHtml(s){return String(s).replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]))}
function renderResult(r,el){
 el.className="result "+r.status.toLowerCase();
 el.innerHTML=`<div class="result-grid"><div><div class="eyebrow">DESTINATION</div><h2>${escapeHtml(r.url)}</h2><div class="status ${r.status.toLowerCase()}">${r.status} • ${r.level}</div></div><div class="score ${r.status.toLowerCase()}">${r.score}<small>/100</small></div></div><h3>Detection Details</h3><ul class="reasons">${r.reasons.map(x=>`<li>✓ ${escapeHtml(x)}</li>`).join("")}</ul>${r.status==="MALICIOUS"?'<a class="btn danger" href="/blocked">ACCESS BLOCKED — VIEW PAGE</a>':'<a class="btn primary" href="/analysis">VIEW FULL ANALYSIS</a>'}`;
 try{sessionStorage.setItem("guardResult",JSON.stringify(r))}catch{}
}
