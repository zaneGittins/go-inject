/*
   Yara Rule Set
   Author: Zane Gittins
   Date: 2022-07-01
   Identifier: GO-Inject Binary
   Reference: https://github.com/zaneGittins/go-inject
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule GOInject_Malware_Jul01_1 {
   meta:
      description = "Detects GOInject"
      author = "Zane Gittins"
      reference = "https://github.com/zaneGittins/go-inject"
      date = "2022-07-01"
   strings:
      $s1 = "go-inject/inject.init" fullword ascii
      $s2 = "go-inject/inject/kernel32.go" fullword ascii
      $s3 = "go-inject/inject/ntdll.go" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500MB and (
         pe.section_index(".symtab") and
         any of them
      )
}

rule GOInject_Malware_Jul01_2 {
   meta:
      description = "Detects GOInject"
      author = "Zane Gittins"
      reference = "https://github.com/zaneGittins/go-inject"
      date = "2022-07-01"
   strings:
      $s1 = "fc4883e4f0e8c" nocase
      $s2 = "fce8820000006" nocase
      $s3 = "golang.org/x/sys/windows" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500MB and (
         pe.section_index(".symtab") and
         ($s1 or $s2) and $s3
      )
}
