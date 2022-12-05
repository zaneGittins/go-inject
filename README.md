# go-inject

Process injection techniques written in Go. I've also expanded this repo to include some general offense techniques in Go.

## Techniques

* [Classic virtual alloc](examples/x64/valloc/valloc.go)
* [Heap](examples/x64/heap/heap.go)
* [Remote Thread Injection](examples/x64/remote-thread/remote_thread.go)
* [APC Queue Code Injection](examples/x64/queue-user-apc/queue.go)
* [UUID Injection - Used by Lazarus 2021](examples/x64/uuid/uuid.go)
* [Hook detection](examples/x64/detect-hooks/detect-hooks.go)
* [Keylogger](examples/x64/keylog/keylog.go)
* [Hollow](examples/x64/hollow/hollow.go)
* [API Hashing](examples/x64/api_hash/api_hash.go)

## Usage

Use msfvenom or any other tool to generate hex encoded shellcode:
```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f hex
```

Place hex encoded payload within one of the example .go files replacing the content of the `payload` variable. You can cross compile on Linux using the following:
Linux:
```bash
env GOOS=windows go build -ldflags="-s -w" -trimpath examples/x64/uuid/uuid.go
```

## Detection

I've written a few simple yara rules to detect binaries using go-inject:

[Yara ruleset](yara/goinject.yar)

I also recommend using Sysmon event ids 8 (CreateRemoteThread) and 25 (ProcessTampering) for detection.

## References

* https://blog.sunggwanchoi.com/eng-uuid-shellcode-execution/
* https://github.com/Adepts-Of-0xCC/VBA-macro-experiments/blob/main/EDRHookDetector.vba
* https://github.com/brimstone/go-shellcode
* https://github.com/sysdream/hershell
* https://github.com/yoda66/MalwareDevTalk
* https://labs.jumpsec.com/2019/06/20/bypassing-antivirus-with-golang-gopher-it/
* https://medium.com/@justen.walker/breaking-all-the-rules-using-go-to-call-windows-api-2cbfd8c79724
* https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa
* https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/
* https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection
* https://github.com/abdullah2993/go-runpe
