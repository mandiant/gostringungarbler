// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ----------------------------------------------------------------------

import "vt"

rule Garbled_PE_ELF64
{
  meta:
    author = "chuongdong@google.com"
    description = "Rule for hunting ELF and PE 64-bit garble-obfuscated Golang malicious samples"
  strings:
    $a = "GOMAXPROCS"

    $V21_V23_STACK_EPILOGUE_PATTERN = /\x48\x8D[\x5C\x9C][\S\s]{2,5}\xB9[\S\s]{4}[\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48[\x81\x83][\S\s]{2,5}\x5D\xC3/
    $V21_V23_SPLIT_EPILOGUE_PATTERN = /\x31\xC0\x48\x89[\S\s]\x48\x89[\S\s][\x66\x90]*[\x0F\x1F\x40\x00]*\xE8[\S\s]{4}\x48[\x81\x83][\S\s]{2,5}\x5D\xC3/
    $V21_V23_SEED_EPILOGUE_PATTERN = /\x48\x8b[\S\s]\x48\x8b[\S\s]{2}\x31\xC0[\x66\x90]*[\x0F\x1F\x40\x00]*\xE8[\S\s]{4}\x48[\x81\x83][\S\s]{2,5}\x5D\xC3/
    
    $OLD_STACK_EPILOGUE_PATTERN = /\x48\x8D[\x5C\x9C][\S\s]{2,5}\xB9[\S\s]{4}[\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48\x8B[\S\s]{3,6}\x48[\x81\x83][\S\s]{2,5}\xC3/
    $OLD_SPLIT_EPILOGUE_PATTERN = /\x31\xC0\x48\x89[\S\s]\x48\x89[\S\s][\x66\x90]*[\x0F\x1F\x40\x00]*\xE8[\S\s]{4}\x48\x8B[\S\s]{3,6}\x48[\x81\x83][\S\s]{2,5}\xC3/
    $OLD_SEED_EPILOGUE_PATTERN = /\x48\x8b[\S\s]\x48\x8b[\S\s]{2}\x31\xC0[\x66\x90]*[\x0F\x1F\x40\x00]*\xE8[\S\s]{4}\x48\x8b[\S\s]{3,6}\x48[\x81\x83][\S\s]{2,5}\xC3/

    $PE_header = {50 45 00 00 64}
    $ELF_header = "ELF"
  condition:
    $a and vt.metadata.analysis_stats.malicious >= 5 
        and ((#V21_V23_STACK_EPILOGUE_PATTERN > 30 and #V21_V23_SPLIT_EPILOGUE_PATTERN > 30 or #V21_V23_SEED_EPILOGUE_PATTERN > 30)
            or (#OLD_STACK_EPILOGUE_PATTERN > 30 and #OLD_SPLIT_EPILOGUE_PATTERN > 30 or #OLD_SEED_EPILOGUE_PATTERN > 30))
                and ($PE_header in (0..500) or $ELF_header in (0..100))
}

rule Garbled_PE_ELF86
{
  meta:
    author = "chuongdong@google.com"
    description = "Rule for hunting ELF and PE 32-bit garble-obfuscated Golang malicious samples"
  strings:
    $a = "GOMAXPROCS"

    $STACK_EPILOGUE_PATTERN = /\x89\x44\x24\x04\xC7\x44\x24\x08[\S\s]{4}\xE8[\S\s]{4}\x8B\x44\x24\x0c\x8B\x4C\x24\x10\x89\x44\x24[\S\s]\x89\x4C\x24[\S\s]\x83\xC4[\S\s]\xC3/
    $SPLIT_EPILOGUE_PATTERN = /\x89\x6C\x24\x04\x89\x74\x24\x08\xE8[\S\s]{4}\x8B\x44\x24\x0c\x8B\x4C\x24\x10\x89\x44\x24[\S\s]\x89\x4C\x24[\S\s]\x83\xC4[\S\s]\xC3/
    $SEED_EPILOGUE_PATTERN = /\x89\x4C\x24\x04\x89\x44\x24\x08\xE8[\S\s]{4}\x8B\x44\x24\x0c\x8B\x4C\x24\x10\x89\x44\x24[\S\s]\x89\x4C\x24[\S\s]\x83\xC4[\S\s]\xC3/

    $PE_header = {50 45 00 00 64}
    $ELF_header = "ELF"
  condition:
    $a and vt.metadata.analysis_stats.malicious >= 5 
        and ((#STACK_EPILOGUE_PATTERN > 30 and #SPLIT_EPILOGUE_PATTERN > 30 or #SEED_EPILOGUE_PATTERN > 30)
            or (#STACK_EPILOGUE_PATTERN > 30 and #SPLIT_EPILOGUE_PATTERN > 30 or #SEED_EPILOGUE_PATTERN > 30))
                and ($PE_header in (0..500) or $ELF_header in (0..100))
}