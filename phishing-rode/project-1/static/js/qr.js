let extracted="";
const file=document.getElementById("qrFile"), status=document.getElementById("qrStatus"), urlBox=document.getElementById("qrUrl"), btn=document.getElementById("analyzeQr"), out=document.getElementById("qrResult");
file.addEventListener("change",()=>{
 const selectedFile=file.files[0];
 if(!selectedFile)return;
 extracted="";
 btn.disabled=true;
 urlBox.textContent="Waiting for QR scan…";
 out.className="result hidden";
 status.textContent="Reading QR image…";
 const objectUrl=URL.createObjectURL(selectedFile), img=new Image();
 img.onload=()=>{
  try{
   const c=document.createElement("canvas"),x=c.getContext("2d"); c.width=img.naturalWidth;c.height=img.naturalHeight;x.drawImage(img,0,0);
   const code=window.jsQR?jsQR(x.getImageData(0,0,c.width,c.height).data,c.width,c.height,{inversionAttempts:"attemptBoth"}):null;
   if(code){extracted=code.data;urlBox.textContent=extracted;btn.disabled=false;status.textContent="QR decoded successfully."}
   else{status.textContent="No readable QR code found. Try a clearer image."}
  }finally{URL.revokeObjectURL(objectUrl)}
 };
 img.onerror=()=>{URL.revokeObjectURL(objectUrl);status.textContent="The selected image could not be read."};
 img.src=objectUrl;
});
btn.addEventListener("click",async()=>{
 btn.disabled=true;out.className="result";out.textContent="Analyzing extracted URL…";
 const res=await fetch("/api/qr-result",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:extracted})});
 const data=await res.json();btn.disabled=false;
 if(res.ok)renderResult(data,out);else{out.className="result malicious";out.textContent=data.error||"Analysis failed"}
});