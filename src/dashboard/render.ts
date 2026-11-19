/** Gera o dashboard executivo (HTML único, sem dependências) a partir dos dados da auditoria. */
export function renderDashboard(data: unknown): string {
  const json = JSON.stringify(data).replace(/</g, '\\u003c');
  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VoltaSegura · Risco Cidadão</title>
<style>
:root{--ink:#131313;--bone:#f2efe8;--paper:#fbfaf6;--orange:#f25c05;--graphite:#3a3733;--muted:#6d675e;--line:#d9d4c9;--moss:#2e7d5b}
*{box-sizing:border-box}
body{margin:0;background:var(--bone);color:var(--graphite);font:16px/1.55 "Segoe UI",system-ui,sans-serif}
h1,h2,h3,.num{font-family:"Iowan Old Style","Palatino Linotype",Georgia,serif;font-weight:700;margin:0}
.wrap{max-width:1080px;margin:0 auto;padding:0 24px}
header.hero{background:var(--ink);color:#f2efe8;padding:40px 0 56px}
header.hero h1{font-size:clamp(34px,5vw,52px);line-height:1.05}
header.hero p{max-width:60ch;color:#c9c3b8;margin:10px 0 0}
.route{display:grid;grid-template-columns:repeat(3,1fr);gap:0;margin-top:44px;position:relative}
.route::before{content:"";position:absolute;left:8%;right:8%;top:13px;border-top:3px dashed var(--orange)}
.stop{position:relative;padding:0 14px}
.stop::before{content:"";display:block;width:26px;height:26px;border-radius:50%;background:var(--ink);border:4px solid var(--orange);margin-bottom:14px;position:relative}
.stop.ok::before{border-color:var(--moss)}
.stop .num{font-size:clamp(64px,10vw,112px);line-height:1}
.stop.bad .num{color:var(--orange)}
.stop.ok .num{color:#9fd6bb}
.stop h3{font-size:18px;margin-top:6px}
.stop p{margin:4px 0 0;color:#c9c3b8;font-size:14px}
.lvl{display:inline-block;font-weight:600;font-size:14px;margin-left:8px}
section{padding:40px 0 0}
section h2{font-size:26px;margin-bottom:6px}
section>.wrap>p.lead{margin:0 0 20px;color:var(--muted);max-width:70ch}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:32px}
.bar{display:grid;grid-template-columns:150px 1fr 34px;gap:10px;align-items:center;margin:9px 0;font-size:15px}
.bar i{display:block;height:14px;background:var(--orange);border-radius:2px}
.bar b{text-align:right}
.tbl{overflow-x:auto;background:var(--paper);border:1px solid var(--line)}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#ebe7dd;font-weight:600}
code{font:13px/1.4 ui-monospace,Consolas,monospace;background:#ebe7dd;padding:1px 5px}
.ev{background:var(--ink);color:#e9e4d9;padding:14px 16px;font:13px/1.5 ui-monospace,Consolas,monospace;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
.ev em{color:var(--orange);font-style:normal}.ev u{color:#9fd6bb;text-decoration:none}
.alerts{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
.alert{background:var(--paper);border:1px solid var(--line);border-left:5px solid var(--orange);padding:16px 18px}
.alert.critical{border-left-color:#b3261e}
.alert h3{font-size:18px;margin-bottom:6px}
.alert p{margin:6px 0;font-size:14.5px}.alert small{color:var(--muted)}
footer{padding:44px 0 56px;color:var(--muted);font-size:13.5px}
footer p{max-width:80ch;margin:6px 0}
:focus-visible{outline:3px solid var(--orange);outline-offset:2px}
@media(max-width:760px){.route{grid-template-columns:1fr;gap:28px}.route::before{left:13px;right:auto;top:0;bottom:0;border-top:0;border-left:3px dashed var(--orange)}.stop{padding-left:44px}.stop::before{position:absolute;left:0;top:0;margin:0}.cols{grid-template-columns:1fr}.bar{grid-template-columns:120px 1fr 30px}}
</style>
</head>
<body>
<header class="hero"><div class="wrap">
<h1>Risco Cidadão</h1>
<p>O quanto dos dados pessoais de quem usa o VoltaSegura escapa do lugar protegido (logs, relatórios de erro, análises de uso e serviços de IA).</p>
<div class="route" id="route"></div>
</div></header>
<main>
<section><div class="wrap"><h2>Para onde os dados escapam</h2><p class="lead">Vazamentos únicos por destino e por tipo de dado, no app antes da correção.</p>
<div class="cols"><div id="sinks"></div><div id="cats"></div></div></div></section>
<section><div class="wrap"><h2>O que isso significa para o cidadão</h2><p class="lead" id="aiLead"></p><div class="alerts" id="alerts"></div></div></section>
<section><div class="wrap"><h2>Onde está no código</h2><p class="lead" id="stLead"></p><div class="tbl"><table id="flows"></table></div></div></section>
<section><div class="wrap"><h2>Evidência de bloqueio</h2><p class="lead">A mesma linha de log da consulta de rota, sem e com o Taint Analysis em modo de bloqueio.</p><div class="ev" id="ev"></div></div></section>
</main>
<footer><div class="wrap" id="foot"></div></footer>
<script type="application/json" id="d">${json}</script>
<script>
const D=JSON.parse(document.getElementById('d').textContent);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const SINK={log:'Logs internos',errorReport:'Relatórios de erro',analytics:'Análise de uso',llm:'IA externa'};
const CAT={localizacao:'Localização',contato:'Contato',credencial:'Credenciais',identificador:'Identificadores',saude:'Saúde',financeiro:'Financeiro',rede:'Rede'};
const R=D.risco;
const stop=(cls,r,t,p)=>'<div class="stop '+cls+'"><div class="num">'+r.score+'</div><h3>'+t+'<span class="lvl">'+r.level+'</span></h3><p>'+p+'</p></div>';
document.getElementById('route').innerHTML=
 stop('bad',R.antes,'Antes da correção',R.antes.leaks+' vazamentos únicos em '+D.saidasVazadas+' saídas')+
 stop('ok',R.bloqueio,'Com bloqueio em tempo real',R.bloqueio.blocked+' vazamentos bloqueados antes de sair')+
 stop('ok',R.depois,'Código corrigido',R.depois.leaks+' vazamentos nos '+D.cenarios+' cenários testados');
const bars=(o,names)=>{const m=Math.max(1,...Object.values(o));return Object.entries(o).sort((a,b)=>b[1]-a[1]).map(([k,v])=>'<div class="bar"><span>'+(names[k]||k)+'</span><i style="width:'+(v/m*100)+'%"></i><b>'+v+'</b></div>').join('')};
document.getElementById('sinks').innerHTML='<h3>Por destino</h3>'+bars(R.antes.bySink,SINK);
document.getElementById('cats').innerHTML='<h3>Por tipo de dado</h3>'+bars(R.antes.byCategory,CAT);
document.getElementById('aiLead').textContent=D.ia==='llm'?'Alertas escritos por um modelo de linguagem a partir de achados sem dado pessoal.':'Alertas gerados pelo modo offline (GEMINI_API_KEY não definida); com a chave, o Gemini escreve os alertas recebendo apenas achados sem dado pessoal.';
document.getElementById('alerts').innerHTML=D.alertas.map(a=>'<article class="alert '+a.severity+'"><h3>'+esc(a.titulo)+'</h3><p>'+esc(a.riscoReal)+'</p><p><strong>O que fazer:</strong> '+esc(a.oQueFazer)+'</p><small>Correção técnica: '+esc(a.correcaoTecnica)+'</small></article>').join('');
document.getElementById('stLead').textContent=D.estatica.antes.length+' caminhos de dado do usuário até um destino inseguro no código vulnerável; '+D.estatica.depois.length+' no código corrigido.';
document.getElementById('flows').innerHTML='<tr><th>Arquivo:linha</th><th>Destino</th><th>Origem do dado</th><th>Tipo</th></tr>'+D.estatica.antes.map(f=>'<tr><td><code>'+esc(f.file)+':'+f.line+'</code></td><td>'+esc(f.sink)+'</td><td>'+esc(f.sources.join(', '))+'</td><td>'+esc(f.categories.map(c=>CAT[c]||c).join(', '))+'</td></tr>').join('');
document.getElementById('ev').innerHTML='<em>sem bloqueio →</em> '+esc(D.evidencia.antes)+'\\n<u>com bloqueio →</u> '+esc(D.evidencia.bloqueio);
document.getElementById('foot').innerHTML='<p><strong>Como ler o indicador.</strong> Vai de 0 a 100 e mede o risco aos dados pessoais de quem usa o app, nunca o risco de uma rua, bairro ou região. Cada vazamento único pesa severidade × exposição do destino (×1,25 se for dado de saúde); score = 100 × (1 − e^(−soma/'+D.formula.K+')).</p><p><strong>Limites.</strong> Dados 100% sintéticos, '+D.cenarios+' cenários e '+D.ruleCount+' regras de PII. Zero vazamento nesses cenários não prova ausência de vazamento em produção, e este material não afirma conformidade com a LGPD.</p><p>Gerado em '+esc(D.geradoEm)+'.</p>';
</script>
</body>
</html>
`;
}
