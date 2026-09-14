import hashlib, http.server, json, os, pathlib, socket, sqlite3, subprocess, tempfile, threading, time
binary=str(pathlib.Path(__file__).resolve().parents[1]/'target/debug/ecco')
with tempfile.TemporaryDirectory(prefix='ecco-native-smoke-') as directory:
 root=pathlib.Path(directory); user=root/'user'; user.mkdir(); bins=root/'bin'; bins.mkdir()
 env={'HOME':str(user),'PATH':str(bins)+':/usr/bin:/bin','XDG_CONFIG_HOME':str(user/'.config')}
 def executable(path,text):path.write_text(text);path.chmod(0o700)
 service_log=root/'service.log'; fail=root/'fail-start'
 executable(bins/'systemctl', '#!/bin/sh\nprintf "%s\\n" "$*" >> '+str(service_log)+'\ncase "$2" in is-active|is-enabled) exit 1;; start) [ ! -f '+str(fail)+' ];; *) exit 0;; esac\n')
 def run(home,*args,check=True):
  r=subprocess.run([binary,'--home',str(home),*args],env=env,text=True,capture_output=True,timeout=20)
  if check and r.returncode:raise AssertionError((args,r.stderr,r.stdout))
  return r
 with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 relay=subprocess.Popen([binary,'relay','--port',str(port),'--data',str(root/'relay'),'--signed'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 reports=[];traces=[];fail_upload=[False]
 class Dashboard(http.server.BaseHTTPRequestHandler):
  def do_POST(self):
   data=self.rfile.read(int(self.headers['content-length']));body=([json.loads(line) for line in data.decode().splitlines() if line] if self.headers.get('x-trace-format')=='ecco-trace-v1' else json.loads(data))
   if fail_upload[0]:self.send_response(503);self.end_headers();self.wfile.write(b'{}');return
   if self.path=='/api/traces':
    traces.append((self.headers['x-trace-format'],body,self.headers['x-ecco-addr']))
    reply={'hash':'sha256:'+hashlib.sha256(data).hexdigest()}
   else:reports.append(body);reply={'accepted':len(body['events'])}
   self.send_response(200);self.end_headers();self.wfile.write(json.dumps(reply).encode())
  def log_message(self,*args):pass
 dashboard=http.server.ThreadingHTTPServer(('127.0.0.1',0),Dashboard);threading.Thread(target=dashboard.serve_forever,daemon=True).start();api='http://127.0.0.1:'+str(dashboard.server_port)
 try:
  for _ in range(60):
   try:
    with socket.create_connection(('127.0.0.1',port),.1):break
   except OSError:time.sleep(.05)
  homes={n:root/n for n in ['alice','bob']};authority='localhost:'+str(port)
  for n,h in homes.items():run(h,'init','--name',n,'--relay','http://localhost:'+str(port),'--no-integrations')
  alice=homes['alice'];bob=homes['bob']
  run(alice,'traces','install','--from','codex','--api',api)
  hooks=json.loads((user/'.codex/hooks.json').read_text())['hooks'];assert 'Stop' in hooks and hooks['Stop'][0]['hooks'][0]['async']
  assert 'ecco-ops' not in json.dumps(hooks)
  before=(alice/'identity.json').read_bytes();run(alice,'traces','install','--from','codex');assert (alice/'identity.json').read_bytes()==before
  handler=root/'handler';calls=root/'calls'
  executable(handler,'#!/bin/sh\ncat >/dev/null\nprintf x >> '+str(calls)+'\nprintf \'%s\' \'{"kind":"finding","text":"pong","follow_up":"one clarification"}\'\n')
  args=['dispatcher','install','--handler',str(handler),'--allow','bob@'+authority,'--workdir',str(root)]
  fail.touch();assert run(alice,*args,check=False).returncode!=0;assert not (alice/'dispatcher/config.json').exists();fail.unlink()
  run(alice,*args);assert json.loads((alice/'contacts.json').read_text())['bob@'+authority]=='approved';units=list((user/'.config/systemd/user').glob('*.service'));assert len(units)==1
  unit=units[0];assert 'ecco-ops' not in unit.read_text() and 'dispatcher' in unit.read_text();assert unit.stat().st_mode&0o777==0o600
  previous=unit.read_bytes();config=(alice/'dispatcher/config.json').read_bytes();fail.touch();assert run(alice,*args,check=False).returncode!=0;assert unit.read_bytes()==previous;assert (alice/'dispatcher/config.json').read_bytes()==config;fail.unlink()
  request=json.loads(run(bob,'send','--to','alice@'+authority,'--about','smoke','--kind','request','ping').stdout)
  # Keep all uploads queued through execution and simulate restart with persisted result.
  fail_upload[0]=True;run(alice,'dispatcher','run','--once');assert calls.read_text()=='x'
  db=sqlite3.connect(alice/'dispatcher.sqlite');assert db.execute('SELECT status FROM jobs').fetchone()[0]=='completed'
  db.execute("UPDATE jobs SET status='running'");db.commit();fail_upload[0]=False
  run(alice,'dispatcher','run','--once');assert calls.read_text()=='x'
  messages=json.loads(run(bob,'log','smoke','--json').stdout)['messages'];assert len(messages)==3,messages
  assert len([m for m in messages if m['env']['kind']=='finding'])==1
  assert all(m['env']['body']['in_reply_to']==request['id'] for m in messages if m['env']['from'].startswith('alice@'))
  assert reports and any(e['state']=='completed' for report in reports for e in report['events'])
  assert db.execute('SELECT count(*) FROM report_outbox').fetchone()[0]==0
  assert traces
  dispatcher_traces=[body for fmt,body,addr in traces if fmt=='ecco-trace-v1'];assert dispatcher_traces
  events=dispatcher_traces[-1]
  assert len([e for e in events if e.get('direction')=='sent'])==2,events
  assert len([e for e in events if e.get('direction')=='received'])==1,events
  native=root/'native.jsonl';native.write_text('{"type":"event_msg","timestamp":"2026-09-14T00:00:00Z","payload":{"type":"user_message","message":"hi"}}\n')
  fail_upload[0]=True;run(alice,'traces','push','--from','codex','--transcript',str(native))
  fail_upload[0]=False;run(alice,'traces','retry');assert any(fmt=='ecco-native-v1' and body['agent']=='codex' for fmt,body,addr in traces)
  run(alice,'dispatcher','uninstall');assert not unit.exists();assert (alice/'dispatcher.sqlite').exists()
  print('PASS native service install/rollback, capture setup, queue restart, no duplicate replies, follow-up, trace and report retries; no Ops helper')
 finally:
  relay.terminate();relay.wait(timeout=5);dashboard.shutdown();dashboard.server_close()
