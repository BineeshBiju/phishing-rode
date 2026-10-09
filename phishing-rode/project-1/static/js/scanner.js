document.getElementById("checkBtn").addEventListener("click",async()=>{
 const url=document.getElementById("urlInput").value.trim(), el=document.getElementById("scanResult");
 if(!url){el.className="result";el.textContent="Please enter a URL.";return}
 el.className="result";el.textContent="Analyzing…";
 try{
  const res=await fetch("/api/check-url",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url})});
  const data=await res.json(); if(!res.ok) throw new Error(data.error||"Scan failed");
  renderResult(data,el);
 }catch(e){el.className="result malicious";el.textContent=e.message}
});

document.getElementById("urlInput").addEventListener("keydown",(e)=>{
 if(e.key==="Enter"){
  e.preventDefault();
  document.getElementById("checkBtn").click();
 }
});