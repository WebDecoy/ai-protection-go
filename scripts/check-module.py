#!/usr/bin/env python3
"""Build a private module zip from an explicit allowlist and install it in isolation.
No repository creation, upload, public checksum query or source license grant.
"""
import hashlib,json,os,pathlib,subprocess,tempfile,zipfile
root=pathlib.Path(__file__).resolve().parents[1]
go_bin=str(pathlib.Path(subprocess.check_output(['go','env','GOROOT'],text=True).strip())/'bin/go')
module='github.com/WebDecoy/ai-protection-go'
version='v0.1.0-alpha.2'
expected={'actions.go','go.mod','README.md','LICENSE','NOTICE','budget.go','browser_evidence.go','concurrency.go','protection.go','account_quota.go','reporting.go','transport.go','usage.go'}
actual={p.name for p in root.glob('*.go') if not p.name.endswith('_test.go')}|{'go.mod','README.md','LICENSE','NOTICE'}
if actual!=expected:raise SystemExit('Review the module artifact allowlist: '+str(actual^expected))
with tempfile.TemporaryDirectory(prefix='webdecoy-module-') as tmp:
 tmp=pathlib.Path(tmp);proxy=tmp/'proxy';target=proxy/'github.com/!web!decoy/ai-protection-go/@v';target.mkdir(parents=True)
 archive=target/(version+'.zip')
 with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
  for name in sorted(expected):
   info=zipfile.ZipInfo(module+'@'+version+'/'+name,date_time=(1980,1,1,0,0,0));info.external_attr=0o644<<16
   z.writestr(info,(root/name).read_bytes())
 (target/(version+'.mod')).write_bytes((root/'go.mod').read_bytes())
 (target/(version+'.info')).write_text(json.dumps({'Version':version,'Time':'2026-09-28T00:00:00Z'}))
 consumer=tmp/'consumer';consumer.mkdir();(consumer/'go.mod').write_text('module isolatedconsumer\ngo 1.26.1\nrequire '+module+' '+version+'\n')
 (consumer/'main.go').write_text('package main\nimport(p "'+module+'";"fmt")\nfunc main(){c,e:=p.New(p.Config[string]{BaseURL:"https://ingest.invalid",APIKey:"fixture",PropertyID:"11111111-1111-4111-8111-111111111111",DisableCentralReporting:true});if e!=nil||c==nil{panic("module contract")};fmt.Println("isolated module imports and constructs client") }\n')
 env=os.environ.copy();env.update(GOPROXY=proxy.as_uri(),GOSUMDB='off',GONOSUMDB='*',GONOPROXY='',GOMODCACHE=str(tmp/'modcache'),GOWORK='off',GOFLAGS='-mod=mod',GOTOOLCHAIN='local')
 subprocess.run([go_bin,'run','.'],cwd=consumer,env=env,check=True)
 print(json.dumps({'artifact':module+'@'+version,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'files':sorted(expected),'validation':'local artifact consumer passed'}))
