# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# ----------------------------------------------------------------------

import argparse
from typing import Literal
import lief
import logging as logger
import datetime
import ungarblers
import patterns
import patchers

def get_binary_architecture(lief_binary: lief.Binary) -> Literal['386', 'AMD64']:
    """Get the binary architecture
    Args:
        lief_binary (lief.Binary): Binary object of the PE

    Raises:
        Exception: Architecture not supported

    Returns:
        str: Binary architecture
    """
    if isinstance(lief_binary, lief.PE.Binary):
        if lief_binary.header.machine == lief.PE.Header.MACHINE_TYPES.I386:
            return '386'
        elif lief_binary.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64:
            return 'AMD64'

    elif isinstance(lief_binary, lief.ELF.Binary):
        if lief_binary.header.identity_class == lief.ELF.Header.CLASS.ELF32.value:
            return '386'
        elif lief_binary.header.identity_class == lief.ELF.Header.CLASS.ELF64.value:
            return 'AMD64'

    raise Exception("Architecture not supported")

def main() -> None:
    parser = argparse.ArgumentParser(prog='GoStringUngarbler', description='Python project to deobfuscate strings in Go binaries protected by garble')
    parser.add_argument('-i', '--input', type=str, help='Garble-obfuscated executable path', required=True)
    parser.add_argument('-o', '--output', type=str, help='Deobfuscated output executable path')
    parser.add_argument('-s', '--string', type=str, help='Extracted string output path')
    
    args = parser.parse_args()
    
    if args.input is None:
        parser.error("Input file is required")

    logger.basicConfig(level=logger.INFO)

    input_file = open(args.input, 'rb')
    input_data = input_file.read()
    input_file.close()
    
    lief_binary = lief.parse(input_data)
    if lief_binary is None:
        raise Exception("Not a valid PE/ELF file")
    
    try:
        pe_architecture = get_binary_architecture(lief_binary)
    except Exception as e:
        print(e)
        exit()

    if pe_architecture == '386':
        ungarbler = ungarblers.GoStringUngarblerX86(lief_binary, input_data)
        garble_pattern = patterns.GarblerPatternX86(input_data)
        patcher_engine = patchers.PatcherX86(garble_pattern)
    elif pe_architecture == 'AMD64':
        ungarbler = ungarblers.GoStringUngarblerX64(lief_binary, input_data)
        garble_pattern = patterns.GarblerPatternX64(input_data)
        patcher_engine = patchers.PatcherX64(garble_pattern)
    
    start = datetime.datetime.now()
    
    ungarbler.find_string_decryption_routine(patterns.STACK_STRING_DECRYPTION, garble_pattern)
    ungarbler.find_string_decryption_routine(patterns.SPLIT_STRING_DECRYPTION, garble_pattern)
    ungarbler.find_string_decryption_routine(patterns.SEED_STRING_DECRYPTION, garble_pattern)
    
    error_count = 0
    error_list_func = []

    for i in range(len(ungarbler.decrypt_func_list)):
        func = ungarbler.decrypt_func_list[i]
        try:
            decrypted_str = ungarbler.emulate(func)

            if len(decrypted_str) != 0:
                func.set_decrypted_string(decrypted_str)
                logger.info('%s in %s | result at 0x%x: %s', str(i + 1), str(len(ungarbler.decrypt_func_list)), func.func_start_va, repr(decrypted_str))
                patcher_engine.generate_patch(func)
        except Exception as e:
            logger.debug('Emulation error: %s', str(e))
            error_list_func.append(func)
            error_count += 1

    logger.info("Error occured: %d", error_count)

    logger.info("Stack obfuscated string count: %d strings.", ungarbler.stack_func_count)
    logger.info("Split obfuscated string count: %d strings.", ungarbler.split_func_count)
    logger.info("Seed obfuscated string count: %d strings.", ungarbler.seed_func_count)
    
    # if -o/--output is provided, perform patching
    if args.output is not None:
        try:
            logger.info('Done generating patches for %d functions. Applying patches to %s', len(ungarbler.decrypt_func_list) - error_count, args.output)
            
            # create output file by copying input file to output
            output_data = patcher_engine.apply_patches(input_data)

            output_file = open(args.output, 'wb')
            
            output_file.write(output_data)
            
            output_file.close()
            logger.info('Result has been written to %s', args.output)
        except Exception as e:
            logger.debug('Patching error: %s', str(e))

    # if -s/--string is provided, dump string
    if args.string is not None:
        logger.info('Dump extracted strings to %s', args.string)
        
        string_dump = open(args.string, 'w')
        for func in ungarbler.decrypt_func_list:
            if len(func.decrypted_string) != 0:
                string_dump.write(repr(func.decrypted_string) + '\n')
        
        string_dump.close()
    
    end = datetime.datetime.now()
    length = end - start
    logger.info("Processing took %d ms!", length.total_seconds() * 1000)
    
if __name__ == '__main__':
    main()