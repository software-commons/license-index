const rotate = (n, b) => (n >>> b) | (n << (32 - b));
const constants = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];
function sha256Ascii(source) {
  if (!/^[\x00-\x7f]*$/.test(source) || source.length > 65536) throw Error("Unexpected digest input");
  const words = [];
  for (let i = 0; i < source.length; i++) words[i >> 2] = (words[i >> 2] || 0) | (source.charCodeAt(i) << (24 - (i % 4) * 8));
  const i = source.length;
  words[i >> 2] = (words[i >> 2] || 0) | (0x80 << (24 - (i % 4) * 8));
  words[(((i + 8) >> 6) << 4) + 15] = i * 8;
  const hash = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  for (let offset = 0; offset < words.length; offset += 16) {
    const w = Array.from({length:16}, (_,j) => words[offset+j] | 0);
    for (let j=16; j<64; j++) {
      const x=w[j-15], y=w[j-2];
      w[j]=((rotate(y,17)^rotate(y,19)^(y>>>10))+w[j-7]+(rotate(x,7)^rotate(x,18)^(x>>>3))+w[j-16]) | 0;
    }
    let [a,b,c,d,e,f,g,h]=hash;
    for (let j=0; j<64; j++) {
      const s1=rotate(e,6)^rotate(e,11)^rotate(e,25), choose=(e&f)^(~e&g);
      const first=(h+s1+choose+constants[j]+w[j]) | 0;
      const s0=rotate(a,2)^rotate(a,13)^rotate(a,22), majority=(a&b)^(a&c)^(b&c);
      [a,b,c,d,e,f,g,h]=[(first+s0+majority)|0,a,b,c,(d+first)|0,e,f,g];
    }
    const next=[a,b,c,d,e,f,g,h];
    for (let j=0; j<8; j++) hash[j]=(hash[j]+next[j]) | 0;
  }
  return hash.map(word=>(word>>>0).toString(16).padStart(8,"0")).join("");
}
if(sha256Ascii("abc")!=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") throw Error("SHA-256 self-test failed");

const instruments = ["perimeter","shield"];
function material(alias) {
  const observed = load("polyform-current-"+alias);
  if (!observed || observed.body_encoding!=="utf-8" || observed.bytes!==observed.source_text.length || sha256Ascii(observed.source_text)!==observed.sha256) throw Error("Invalid source body");
  return {digest:observed.sha256, record:JSON.parse(observed.source_text)};
}
const ordered = row => Object.fromEntries(Object.entries(row).sort(([a],[b]) => a<b?-1:a>b?1:0));
const repr = (id,origin) => JSON.stringify({candidate_id:id,origin:ordered(origin)})+"\n";
const rows = instruments.map(instrument => {
  const prior = material(instrument+"_discovery");
  const fresh = material(instrument+"_accepted");
  const first=prior.record, last=fresh.record;
  if(first.id!==last.id || first.disposition!=="unresolved" || last.disposition!=="accepted") throw Error("Invalid transition");
  const before=repr(first.id,first.origin);
  const after=repr(last.id,last.origin);
  if(before!==after) throw Error("Origin changed");
  const tail=last.history.at(-1);
  if(last.history.length!==first.history.length+1 || JSON.stringify(last.history.slice(0,-1))!==JSON.stringify(first.history) ||
     tail.disposition!==first.disposition || tail.reason!==first.reason || Object.keys(tail).length!==2) throw Error("History discontinuity");
  const origin=sha256Ascii(after);
  const changed=sha256Ascii(repr(last.id,{...last.origin,source:last.origin.source+"#altered"}));
  return {instrument,candidate:last.id,old_source:prior.digest,accepted_source:fresh.digest,origin_sha256:origin,old_disposition:first.disposition,new_disposition:last.disposition,predecessor_preserved:true,changed_locator_differs:origin!==changed};
});
if(rows[0].candidate===rows[1].candidate || rows[0].origin_sha256===rows[1].origin_sha256 || rows.some(row=>!row.changed_locator_differs)) throw Error("Invalid distinct origins");
text("SCES-POLYFORM-ACCEPTED-ORIGIN-REPLAY "+JSON.stringify(rows));
