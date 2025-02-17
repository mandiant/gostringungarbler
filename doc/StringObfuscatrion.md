# Stack Transformation
This method implements runtime encoding to strings stored directly on the stack.

## Simple Transformation

This transformation applies byte-by-byte encoding using a randomly generated mathematical operator and a randomly generated key of equal length to the input string and.

Obfuscator implementation: https://github.com/burrowers/garble/blob/master/internal/literals/simple.go

garble's obfuscator code:

``` go
// Generate a random key with the same length as the input string
key := make([]byte, len(data))

// Fill the key with random bytes
obfRand.Read(key)

// Select a random operator (XOR, ADD, SUB) to be used for encryption
op := randOperator(obfRand)

// Encrypt each byte of the data with the key using the random operator
for i, b := range key {
    data[i] = evalOperator(op, data[i], b)
}
```

Decompiled code of decoding subroutine:

``` C
void __fastcall sub_6259A0()
{
    if ( &retaddr <= *(v0 + 16) )
        sub_457960();
    *key = 1853338368;
    *&key[3] = 0xA94A691DB88A216ELL;
    *&key[11] = 0xE2CEB62309E6CA57LL;
    *data = 186376041;
    *&data[3] = 0xDA24003DD4EB460BLL;
    *&data[11] = 0x8CA1DF576A93B823LL;
    for ( i = 0LL; i < 19; ++i )
        data[i] ^= key[i];
    runtime_slicebytetostring(data, 19);
}
```

## Swap Transformation

This transformation applies a combination of byte-pair swapping and position-dependent encoding, where pairs of bytes are shuffled and encrypted using dynamically generated local keys.

Obfuscator implementation: https://github.com/burrowers/garble/blob/master/internal/literals/swap.go

garble's obfuscator code:

``` go
// Determines how many swap operations to perform based on data length
func generateSwapCount(obfRand *mathrand.Rand, dataLen int) int {
    // Start with number of swaps equal to data length
    swapCount := dataLen

    // Calculate maximum additional swaps (half of data length)
    maxExtraPositions := dataLen / 2

    // Add a random amount if we can add extra positions 
    if maxExtraPositions > 1 {
        swapCount += obfRand.Intn(maxExtraPositions)
    }

    // Ensure swap count is even by incrementing if odd
    if swapCount%2 != 0 {
        swapCount++
    }
    return swapCount
}

func (swap) obfuscate(obfRand *mathrand.Rand, data []byte) *ast.BlockStmt {
    // Generate number of swap operations to perform
    swapCount := generateSwapCount(obfRand, len(data))

    // Generate a random shift key
    shiftKey := byte(obfRand.Uint32())

    // Select a random reversible operator for encryption
    op := randOperator(obfRand)

    // Generate list of random positions for swapping bytes
    positions := genRandIntSlice(obfRand, len(data), swapCount)

    // Process pairs of positions in reverse order
    for i := len(positions) - 2; i >= 0; i -= 2 {
        // Generate a position-dependent local key for each pair
        localKey := byte(i) + byte(positions[i]^positions[i+1]) + shiftKey
        
        // Perform swap and encryption:
        // - Swap positions[i] and positions[i+1]
        // - Encrypt the byte at each position with the local key
        data[positions[i]], data[positions[i+1]] = evalOperator(op, data[positions[i+1]], localKey), evalOperator(op, data[positions[i]], localKey)
    }
...
```

Decompiled code of decoding subroutine:

``` C++
__int64 __fastcall sub_5DAD60()
{
  if ( &retaddr <= *(v0 + 16) )
    sub_457960();
  *data = 0x2663744C4E0A8E80LL;
  *&data[5] = 0x6515C02472266374LL;
  *&data[13] = 0x747870A7A06F63D5LL;
  *&data[21] = 0x203CCDB4634D26EALL;
  *&data[29] = 0x66EC6ED61708AC9LL;
  *positions = 0x203;
  *&positions[2] = 0x101B0A0104041711LL;
  *&positions[10] = 0x221A001E150601LL;
  *&positions[18] = 0x190A01030D150709LL;
  *&positions[26] = 0x121B0B1C1D160024LL;
  *&positions[34] = 0x1718171A1203031BLL;
  *&positions[42] = 0x1619170D1B1B0A21LL;
  for ( i = 0LL; i < 50; i += 2LL )
  {
    v2 = positions[i + 1];
    v1 = positions[i];
    localKey = i + (v2 ^ v1);
    if ( v1 >= 0x25 )
      sub_459FC0();
    v5 = data[v1] + localKey + 31;              // shiftKey = 31
    if ( v2 >= 0x25 )
      sub_459FC0();
    data[v1] = data[v2] + localKey + 31;        // evalOperator(token.ADD)
    data[v2] = v5;
  }
  return runtime_slicebytetostring(data, 37);
}
```

## Shuffle Transformation

This transformation applies multiple layers of encryption by encoding the data with random keys, interleaving the encrypted data with its keys, and applying a permutation with XOR-based index mapping to scatter the encrypted data and keys throughout the final output.

Obfuscator implementation: https://github.com/burrowers/garble/blob/master/internal/literals/shuffle.go

garble's obfuscator code:

``` Go
// Generate a random key with the same length as the original string
key := make([]byte, len(data))
obfRand.Read(key)

// Constants for the index key size bounds
const (
    minIdxKeySize = 2
    maxIdxKeySize = 16
)

// Initialize index key size to minimum value
idxKeySize := minIdxKeySize

// Potentially increase index key size based on input data length
if tmp := obfRand.Intn(len(data)); tmp > idxKeySize {
    idxKeySize = tmp
}

// Cap index key size at maximum value
if idxKeySize > maxIdxKeySize {
    idxKeySize = maxIdxKeySize
}

// Generate a secondary key (index key) for index scrambling
idxKey := make([]byte, idxKeySize)
obfRand.Read(idxKey)

// Create a buffer that will hold both encrypted data and the key
fullData := make([]byte, len(data)+len(key))

// Generate random operators for each position in the full data buffer
operators := make([]token.Token, len(fullData))
for i := range operators {
    operators[i] = randOperator(obfRand)
}

// Encrypt data and store it with its corresponding key
// First half contains encrypted data, second half contains the key
for i, b := range key {
    fullData[i], fullData[i+len(data)] = evalOperator(operators[i], data[i], b), b
}

// Generate a random permutation of indices
shuffledIdxs := obfRand.Perm(len(fullData))

// Apply the permutation to scatter encrypted data and keys
shuffledFullData := make([]byte, len(fullData))
for i, b := range fullData {
    shuffledFullData[shuffledIdxs[i]] = b
}

// Prepare AST expressions for decryption
args := []ast.Expr{ast.NewIdent("data")}
for i := range data {
    // Select a random byte from the index key
    keyIdx := obfRand.Intn(idxKeySize)
    k := int(idxKey[keyIdx])
    
    // Build AST expression for decryption:
    // 1. Uses XOR with index key to find the real positions of data and key
    // 2. Applies reverse operator to decrypt the data using the corresponding key
    args = append(args, operatorToReversedBinaryExpr(
        operators[i],

        // Access encrypted data using XOR-ed index
        ah.IndexExpr("fullData", &ast.BinaryExpr{X: ah.IntLit(shuffledIdxs[i] ^ k), Op: token.XOR, Y: ah.CallExprByName("int", ah.IndexExpr("idxKey", ah.IntLit(keyIdx)))}),
        
        // Access corresponding key using XOR-ed index
        ah.IndexExpr("fullData", &ast.BinaryExpr{X: ah.IntLit(shuffledIdxs[len(data)+i] ^ k), Op: token.XOR, Y: ah.CallExprByName("int", ah.IndexExpr("idxKey", ah.IntLit(keyIdx)))}),
    ))
}
```

ASM code of obfuscated function:
``` assembly
.text:56C520 49 3B 66 10             cmp     rsp, [r14+10h]
.text:56C524 0F 86 B3 01 00 00       jbe     loc_56C6DD
.text:56C52A 48 83 EC 50             sub     rsp, 50h
.text:56C52E 48 89 6C 24 48          mov     [rsp+50h+var_8], rbp
.text:56C533 48 8D 6C 24 48          lea     rbp, [rsp+50h+var_8]
.text:56C538 48 BA F3 35 17 1D 51 4B mov     rdx, 8A794B511D1735F3h
.text:56C538 79 8A
.text:56C542 48 89 54 24 30          mov     [rsp+50h+var_20], rdx
.text:56C547 48 BA D0 CD 69 C1 39 22 mov     rdx, 3EC12239C169CDD0h
.text:56C547 C1 3E
.text:56C551 48 89 54 24 38          mov     [rsp+50h+var_18], rdx
.text:56C556 48 BA ED 46 D3 A7 7B ED mov     rdx, 0F58ED7BA7D346EDh
.text:56C556 58 0F
.text:56C560 48 89 54 24 40          mov     [rsp+50h+var_10], rdx
.text:56C565 48 C7 44 24 23 00 00 00 mov     qword ptr [rsp+50h+a2], 0
.text:56C565 00
.text:56C56E 48 C7 44 24 28 00 00 00 mov     qword ptr [rsp+50h+a2+5], 0
.text:56C56E 00
.text:56C577 0F B6 54 24 31          movzx   edx, byte ptr [rsp+50h+var_20+1]
.text:56C57C 0F B6 74 24 38          movzx   esi, byte ptr [rsp+50h+var_18]
.text:56C581 29 F2                   sub     edx, esi
.text:56C583 0F B6 74 24 3C          movzx   esi, byte ptr [rsp+50h+var_18+4]
.text:56C588 0F B6 7C 24 3B          movzx   edi, byte ptr [rsp+50h+var_18+3]
.text:56C58D 44 0F B6 44 24 3E       movzx   r8d, byte ptr [rsp+50h+var_18+6]
.text:56C593 44 0F B6 4C 24 46       movzx   r9d, byte ptr [rsp+50h+var_10+6]
.text:56C599 44 0F B6 54 24 45       movzx   r10d, byte ptr [rsp+50h+var_10+5]
.text:56C59F 44 0F B6 5C 24 36       movzx   r11d, byte ptr [rsp+50h+var_20+6]
.text:56C5A5 44 0F B6 64 24 39       movzx   r12d, byte ptr [rsp+50h+var_18+1]
.text:56C5AB 44 0F B6 6C 24 40       movzx   r13d, byte ptr [rsp+50h+var_10]
.text:56C5B1 44 0F B6 7C 24 34       movzx   r15d, byte ptr [rsp+50h+var_20+4]
.text:56C5B7 44 89 F8                mov     eax, r15d
.text:56C5BA 44 0F B6 7C 24 3D       movzx   r15d, byte ptr [rsp+50h+var_18+5]
.text:56C5C0 44 89 F9                mov     ecx, r15d
.text:56C5C3 44 0F B6 7C 24 3A       movzx   r15d, byte ptr [rsp+50h+var_18+2]
.text:56C5C9 44 89 FB                mov     ebx, r15d
.text:56C5CC 44 0F B6 7C 24 33       movzx   r15d, byte ptr [rsp+50h+var_20+3]
.text:56C5D2 44 88 7C 24 22          mov     [rsp+50h+var_2E], r15b
.text:56C5D7 44 0F B6 7C 24 43       movzx   r15d, byte ptr [rsp+50h+var_10+3]
.text:56C5DD 44 88 7C 24 21          mov     [rsp+50h+var_2F], r15b
.text:56C5E2 44 0F B6 7C 24 41       movzx   r15d, byte ptr [rsp+50h+var_10+1]
.text:56C5E8 44 88 7C 24 20          mov     [rsp+50h+var_30], r15b
.text:56C5ED 44 0F B6 7C 24 30       movzx   r15d, byte ptr [rsp+50h+var_20]
.text:56C5F3 44 88 7C 24 1F          mov     [rsp+50h+var_31], r15b
.text:56C5F8 44 0F B6 7C 24 32       movzx   r15d, byte ptr [rsp+50h+var_20+2]
.text:56C5FE 44 88 7C 24 1E          mov     [rsp+50h+var_32], r15b
.text:56C603 44 0F B6 7C 24 35       movzx   r15d, byte ptr [rsp+50h+var_20+5]
.text:56C609 44 88 7C 24 1D          mov     [rsp+50h+var_33], r15b
.text:56C60E 44 0F B6 7C 24 37       movzx   r15d, byte ptr [rsp+50h+var_20+7]
.text:56C614 44 88 7C 24 1C          mov     [rsp+50h+var_34], r15b
.text:56C619 44 0F B6 7C 24 3F       movzx   r15d, byte ptr [rsp+50h+var_18+7]
.text:56C61F 44 88 7C 24 1B          mov     [rsp+50h+var_35], r15b
.text:56C624 44 0F B6 7C 24 42       movzx   r15d, byte ptr [rsp+50h+var_10+2]
.text:56C62A 44 88 7C 24 1A          mov     [rsp+50h+var_36], r15b
.text:56C62F 44 0F B6 7C 24 44       movzx   r15d, byte ptr [rsp+50h+var_10+4]
.text:56C635 44 88 7C 24 19          mov     [rsp+50h+var_37], r15b
.text:56C63A 44 0F B6 7C 24 47       movzx   r15d, byte ptr [rsp+50h+var_10+7]
.text:56C640 88 54 24 23             mov     byte ptr [rsp+50h+a2], dl
.text:56C644 29 FE                   sub     esi, edi
.text:56C646 40 88 74 24 24          mov     byte ptr [rsp+50h+a2+1], sil
.text:56C64B 45 29 C8                sub     r8d, r9d
.text:56C64E 44 88 44 24 25          mov     byte ptr [rsp+50h+a2+2], r8b
.text:56C653 45 29 DA                sub     r10d, r11d
.text:56C656 44 88 54 24 26          mov     byte ptr [rsp+50h+a2+3], r10b
.text:56C65B 45 31 E5                xor     r13d, r12d                      ; Non-zero XOR
.text:56C65E 44 88 6C 24 27          mov     byte ptr [rsp+50h+a2+4], r13b
.text:56C663 8D 14 08                lea     edx, [rax+rcx]
.text:56C666 88 54 24 28             mov     byte ptr [rsp+50h+a2+5], dl
.text:56C66A 0F B6 54 24 22          movzx   edx, [rsp+50h+var_2E]
.text:56C66F 31 DA                   xor     edx, ebx                        ; Non-zero XOR
.text:56C671 88 54 24 29             mov     byte ptr [rsp+50h+a2+6], dl
.text:56C675 0F B6 54 24 21          movzx   edx, [rsp+50h+var_2F]
.text:56C67A 0F B6 74 24 20          movzx   esi, [rsp+50h+var_30]
.text:56C67F 29 F2                   sub     edx, esi
.text:56C681 88 54 24 2A             mov     byte ptr [rsp+50h+a2+7], dl
.text:56C685 0F B6 54 24 19          movzx   edx, [rsp+50h+var_37]
.text:56C68A 41 31 D7                xor     r15d, edx                       ; Non-zero XOR
.text:56C68D 44 88 7C 24 2B          mov     [rsp+50h+var_25], r15b
.text:56C692 0F B6 54 24 1B          movzx   edx, [rsp+50h+var_35]
.text:56C697 0F B6 74 24 1D          movzx   esi, [rsp+50h+var_33]
.text:56C69C 31 F2                   xor     edx, esi                        ; Non-zero XOR
.text:56C69E 88 54 24 2C             mov     [rsp+50h+var_24], dl
.text:56C6A2 0F B6 54 24 1C          movzx   edx, [rsp+50h+var_34]
.text:56C6A7 0F B6 74 24 1E          movzx   esi, [rsp+50h+var_32]
.text:56C6AC 29 F2                   sub     edx, esi
.text:56C6AE 88 54 24 2D             mov     [rsp+50h+var_23], dl
.text:56C6B2 0F B6 54 24 1A          movzx   edx, [rsp+50h+var_36]
.text:56C6B7 0F B6 74 24 1F          movzx   esi, [rsp+50h+var_31]
.text:56C6BC 31 F2                   xor     edx, esi                        ; Non-zero XOR
.text:56C6BE 88 54 24 2E             mov     [rsp+50h+var_22], dl
.text:56C6C2 31 C0                   xor     eax, eax
.text:56C6C4 48 8D 5C 24 23          lea     rbx, [rsp+50h+a2]               ; a1
.text:56C6C9 B9 0C 00 00 00          mov     ecx, 0Ch                        ; a2
.text:56C6CE E8 0D 9B ED FF          call    runtime_slicebytetostring
.text:56C6D3 48 8B 6C 24 48          mov     rbp, [rsp+50h+var_8]
.text:56C6D8 48 83 C4 50             add     rsp, 50h
.text:56C6DC C3                      retn
```

Decompiled code of decoding subroutine:
(turns out, IDA is pretty good at handling this)

``` C
__int64 __fastcall sub_56C520()
{
  if ( &retaddr <= *(v0 + 16) )
    sub_457960();
  v3 = 0x8A794B511D1735F3LL;
  v4 = 0x3EC12239C169CDD0LL;
  v5 = 0xF58ED7BA7D346EDLL;
  strcpy(a2, "exit status ");
  return runtime_slicebytetostring(a2, 12);
}
```

# Garble's Seed Obfuscation
This method employs a dynamic seed-based encryption mechanism where the seed value evolves with each encoded byte, creating a chain of interdependent encryption operations.

Obfuscator implementation: https://github.com/burrowers/garble/blob/master/internal/literals/seed.go

garble's obfuscator code:

``` go
// Generate random initial seed value
seed := byte(obfRand.Uint32())

// Store original seed for later use in decryption
originalSeed := seed

// Select a random reversible operator for encryption
op := randOperator(obfRand)

var callExpr *ast.CallExpr

// Encrypt each byte while building chain of function calls
for i, b := range data {
   // Encrypt current byte using current seed value
   encB := evalOperator(op, b, seed)

   // Update seed by adding encrypted byte
   seed += encB

   if i == 0 {
       // Start function call chain with first encrypted byte
       callExpr = ah.CallExpr(ast.NewIdent("fnc"), ah.IntLit(int(encB)))
   } else {
       // Add subsequent encrypted bytes to function call chain
       callExpr = ah.CallExpr(callExpr, ah.IntLit(int(encB)))
   }
}
...
```

Decompiled code of decoding subroutine:

```C
__int64 __fastcall sub_46B480(__int64 a1, __int64 a2)
{
    if ( &retaddr <= *(v2 + 16) )
        sub_457960();
    runtime_newobject(a1, a2);
    v28 = v3;
    *v3 = 123;
    runtime_newobject(a1, a2);
    v30 = v4;
    *v4 = 0LL;
    runtime_newobject(a1, a2);
    v29 = v5;
    runtime_newobject(a1, a2);
    *v6 = sub_46B680;
    if ( dword_F32DB0 )
    {
        sub_459C20();
        sub_459C60();
        v7 = v29;
        sub_459C60();
        runtime_gcWriteBarrier();
    }
    else
    {
        v6[1] = v30;
        v6[2] = v28;
        v7 = v29;
        v6[3] = v29;
        *v29 = v6;
    }
    v8 = (**v7)();
    v9 = (*v8)();
    v10 = (*v9)();
    v11 = (*v10)();
    v12 = (*v11)();
    v13 = (*v12)();
    v14 = (*v13)();
    v15 = (*v14)();
    v16 = (*v15)();
    v17 = (*v16)();
    v18 = (*v17)();
    v19 = (*v18)();
    v20 = (*v19)();
    v21 = (*v20)();
    v22 = (*v21)();
    v23 = (*v22)();
    v24 = (*v23)();
    v25 = (*v24)();
    v26 = (*v25)();
    (*v26)();
    return runtime_slicebytetostring(*v30, *(v30 + 1));
}
```

# Garble's Split Obfuscation

This method fragments the encoded strings into multiple chunks, each to be decoded independently in a block of a main switch statement.

Obfuscator implementation: https://github.com/burrowers/garble/blob/master/internal/literals/split.go

``` go
func (split) obfuscate(obfRand *mathrand.Rand, data []byte) *ast.BlockStmt {
    var chunks [][]byte

    // For small input, split into single bytes
    // This ensures even small payloads get sufficient obfuscation
    if len(data)/maxChunkSize < minCaseCount {
        chunks = splitIntoOneByteChunks(data)
    } else {
        chunks = splitIntoRandomChunks(obfRand, data)
    }

    // Generate random indexes for all chunks plus two special cases:
    // - One for the final decrypt operation
    // - One for the exit condition
    indexes := obfRand.Perm(len(chunks) + 2)

    // Initialize the decryption key with a random value
    decryptKeyInitial := byte(obfRand.Uint32())
    decryptKey := decryptKeyInitial
    
    // Calculate the final decrypt key by XORing it with position-dependent values
    for i, index := range indexes[:len(indexes)-1] {
        decryptKey ^= byte(index * i)
    }

    // Select a random reversible operator for encryption
    op := randOperator(obfRand)

    // Encrypt all data chunks using the selected operator and key
    encryptChunks(chunks, op, decryptKey)

    // Get special indexes for decrypt and exit states
    decryptIndex := indexes[len(indexes)-2]
    exitIndex := indexes[len(indexes)-1]
    
    // Create the decrypt case that reassembles the data
    switchCases := []ast.Stmt{&ast.CaseClause{
        List: []ast.Expr{ah.IntLit(decryptIndex)},
        Body: shuffleStmts(obfRand,
            // Exit case: Set next state to exit
            &ast.AssignStmt{
                Lhs: []ast.Expr{ast.NewIdent("i")},
                Tok: token.ASSIGN,
                Rhs: []ast.Expr{ah.IntLit(exitIndex)},
            },
            // Iterate through the assembled data and decrypt each byte
            &ast.RangeStmt{
                Key: ast.NewIdent("y"),
                Tok: token.DEFINE,
                X:   ast.NewIdent("data"),
                Body: ah.BlockStmt(&ast.AssignStmt{
                    Lhs: []ast.Expr{ah.IndexExpr("data", ast.NewIdent("y"))},
                    Tok: token.ASSIGN,
                    Rhs: []ast.Expr{
                        // Apply the reverse of the encryption operation
                        operatorToReversedBinaryExpr(
                            op,
                            ah.IndexExpr("data", ast.NewIdent("y")),
                            // XOR with position-dependent key
                            ah.CallExpr(ast.NewIdent("byte"), &ast.BinaryExpr{
                                X:  ast.NewIdent("decryptKey"),
                                Op: token.XOR,
                                Y:  ast.NewIdent("y"),
                            }),
                        ),
                    },
                }),
            },
        ),
    }}

    // Create switch cases for each chunk of data
    for i := range chunks {
        index := indexes[i]
        nextIndex := indexes[i+1]
        chunk := chunks[i]

        appendCallExpr := &ast.CallExpr{
            Fun:  ast.NewIdent("append"),
            Args: []ast.Expr{ast.NewIdent("data")},
        }
	 ...
        // Create switch case for this chunk
        switchCases = append(switchCases, &ast.CaseClause{
            List: []ast.Expr{ah.IntLit(index)},
            Body: shuffleStmts(obfRand,
                // Set next state
                &ast.AssignStmt{
                    Lhs: []ast.Expr{ast.NewIdent("i")},
                    Tok: token.ASSIGN,
                    Rhs: []ast.Expr{ah.IntLit(nextIndex)},
                },
                // Append this chunk to the collected data
                &ast.AssignStmt{
                    Lhs: []ast.Expr{ast.NewIdent("data")},
                    Tok: token.ASSIGN,
                    Rhs: []ast.Expr{appendCallExpr},
                },
            ),
        })
    }

    // Final block creates the state machine loop structure
    return ah.BlockStmt(
        ...

        // Update decrypt key based on current state and counter
        Body: ah.BlockStmt(
            &ast.AssignStmt{
                Lhs: []ast.Expr{ast.NewIdent("decryptKey")},
                Tok: token.XOR_ASSIGN,
                Rhs: []ast.Expr{
                    &ast.BinaryExpr{
                        X:  ast.NewIdent("i"),
                        Op: token.MUL,
                        Y:  ast.NewIdent("counter"),
                    },
                },
            },
            // Main switch statement as the core of the state machine
            &ast.SwitchStmt{
                Tag:  ast.NewIdent("i"),
                Body: ah.BlockStmt(shuffleStmts(obfRand, switchCases...)...),
            }),
...
```

Decompiled code of decoding subroutine:

``` C
void __fastcall sub_46C640()
{
  if ( &retaddr <= *(v0 + 16) )
    sub_457960();
  *a2 = v1;
  *&a2[5] = v1;
  v2 = 2LL;
  v3 = 164LL;
  v4 = 0LL;
  v5 = 21LL;
  v6 = a2;
  v7 = 0LL;
  while ( v2 != 7 )
  {
    v9 = v2;
    v10 = v3 ^ (v4 * v2);
    v30 = v10;
    v31 = v4;
    switch ( v9 )
    {
      case 0LL:
        v11 = v7 + 2;
        if ( v5 < v7 + 2 )
        {
          v12 = runtime_growslice(2LL, qword_B751E0, v4, v5);
          v4 = v31;
          v6 = v12;
          v11 = v7 + 2;
          v5 = v13;
          v10 = v30;
        }
        *&v6[v7] = -27768;
        v14 = 9LL;
        break;
      case 1LL:
        v11 = v7 + 1;
        if ( v5 < v7 + 1 )
        {
          v15 = runtime_growslice(1LL, qword_B751E0, v4, v5);
          v4 = v31;
          v11 = v7 + 1;
          v6 = v15;
          v5 = v16;
          v10 = v30;
        }
        v6[v11 - 1] = -48;
        v14 = 4LL;
        break;
      case 2LL:
        v11 = v7 + 4;
        if ( v5 < v7 + 4 )
        {
          v17 = runtime_growslice(4LL, qword_B751E0, v4, v5);
          v4 = v31;
          v6 = v17;
          v11 = v7 + 4;
          v5 = v18;
          v10 = v30;
        }
        *&v6[v7] = -556674331;
        v14 = 0LL;
        break;
      case 3LL:
        v11 = v7 + 1;
        if ( v5 < v7 + 1 )
        {
          v19 = runtime_growslice(1LL, qword_B751E0, v4, v5);
          v4 = v31;
          v11 = v7 + 1;
          v6 = v19;
          v5 = v20;
          v10 = v30;
        }
        v6[v11 - 1] = -64;
        v14 = 6LL;
        break;
      case 4LL:
        v11 = v7 + 3;
        if ( v5 < v7 + 3 )
        {
          v21 = runtime_growslice(3LL, qword_B751E0, v4, v5);
          v4 = v31;
          v6 = v21;
          v11 = v7 + 3;
          v5 = v22;
          v10 = v30;
        }
        *&v6[v7] = -8492;
        v6[v7 + 2] = -101;
        v14 = 8LL;
        break;
      case 5LL:
        v11 = v7 + 1;
        if ( v5 < v7 + 1 )
        {
          v23 = runtime_growslice(1LL, qword_B751E0, v4, v5);
          v4 = v31;
          v11 = v7 + 1;
          v6 = v23;
          v5 = v24;
          v10 = v30;
        }
        v6[v11 - 1] = -57;
        v14 = 3LL;
        break;
      case 6LL:
        for ( i = 0LL; v7 > i; ++i )
          v6[i] ^= v10 ^ i;
        v14 = 7LL;
        v11 = v7;
        break;
      case 8LL:
        v11 = v7 + 4;
        if ( v5 < v7 + 4 )
        {
          v26 = runtime_growslice(4LL, qword_B751E0, v4, v5);
          v4 = v31;
          v6 = v26;
          v11 = v7 + 4;
          v10 = v30;
          v5 = v27;
        }
        *&v6[v7] = -909913649;
        v14 = 5LL;
        break;
      case 9LL:
        v11 = v7 + 4;
        if ( v5 < v7 + 4 )
        {
          v28 = runtime_growslice(4LL, qword_B751E0, v4, v5);
          v4 = v31;
          v6 = v28;
          v11 = v7 + 4;
          v5 = v29;
          v10 = v30;
        }
        *&v6[v7] = -557260839;
        v14 = 1LL;
        break;
      default:
        v14 = v9;
        v11 = v7;
        break;
    }
    ++v4;
    v7 = v11;
    v8 = v10;
    v2 = v14;
    v3 = v8;
  }
  runtime_slicebytetostring(v6, v7);
}
```

# String Decoding Subroutine's Regex Patterns (x64)

## Prologue Pattern 

String decryption prologue (same for all 3 decryption types)

``` python
# 49 3B 66 10             cmp     rsp, [r14+10h]
# 0F 86 E5 01 00 00       jbe     loc_B48A0F

# 49 3B 66 10             cmp     rsp, [r14+10h]
# 76 7B                   jbe     short loc_663421

PROLOGUE_PATTERN = rb'[\x49\x4D]\x3B[\S\s]{2}[\x0F\x76]'
```

## Stack Epilogue

V1.21 -> 1.23
``` python
# .text:48F07F 31 C0                                   xor     eax, eax
# .text:48F081 48 8D 5C 24 1D                          lea     rbx, [rsp+30h+var_13]
# .text:48F086 B9 13 00 00 00                          mov     ecx, 13h
# .text:48F08B E8 30 79 FD FF                          call    runtime_slicebytetostring
# .text:48F090 48 83 C4 30                             add     rsp, 30h
# .text:48F094 5D                                      pop     rbp
# .text:48F095 C3                                      retn
V21_V23_STACK_EPILOGUE_PATTERN = rb'\x48\x8D[\x5C\x9C][\S\s]{2,5}\xB9[\S\s]{4}[\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48[\x81\x83][\S\s]{2,5}\x5D\xC3'
```

Older:

```python
# 48 8D 5C 24 7A          lea     rbx, [rsp+128h+a2]
# B9 37 00 00 00          mov     ecx, 37h ; '7'
# E8 AA 6E 97 FF          call    runtime_slicebytetostring
# 48 8B AC 24 20 01 00 00 mov     rbp, [rsp+128h+var_8]
# 48 81 C4 28 01 00 00    add     rsp, 128h
# C3                      retn

OLD_STACK_EPILOGUE_PATTERN = rb'\x48\x8D[\x5C\x9C][\S\s]{2,5}\xB9[\S\s]{4}[\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48\x8B[\S\s]{3,6}\x48[\x81\x83][\S\s]{2,5}\xC3' 
```

## Split Epilogue

V1.21 -> 1.23
```python
# .text:491419 31 C0                                   xor     eax, eax
# .text:49141B 48 89 FB                                mov     rbx, rdi
# .text:49141E 48 89 F1                                mov     rcx, rsi
# .text:491421 E8 9A 55 FD FF                          call    runtime_slicebytetostring
# .text:491426 48 83 C4 50                             add     rsp, 50h
# .text:49142A 5D                                      pop     rbp
# .text:49142B C3                                      retn

V21_V23_SPLIT_EPILOGUE_PATTERN = rb'\x31\xC0\x48\x89[\S\s]\x48\x89[\S\s][\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48[\x81\x83][\S\s]{2,5}\x5D\xC3'
```

Old:
``` python
# 31 C0                   xor     eax, eax
# 48 89 F3                mov     rbx, rsi
# 48 89 F9                mov     rcx, rdi
# E8 83 12 FE FF          call    runtime_slicebytetostring
# 48 8B AC 24 80 00 00 00 mov     rbp, [rsp+88h+var_8]
# 48 81 C4 88 00 00 00    add     rsp, 88h
# C3                      retn

OLD_SPLIT_EPILOGUE_PATTERN = rb'\x31\xC0\x48\x89[\S\s]\x48\x89[\S\s][\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48\x8B[\S\s]{3,6}\x48[\x81\x83][\S\s]{2,5}\xC3'
```

## Seed Epilogue

V1.21 -> 1.23
```python
# .text:495A55 48 8B 19                                mov     rbx, [rcx]
# .text:495A58 48 8B 49 08                             mov     rcx, [rcx+8]
# .text:495A5C 31 C0                                   xor     eax, eax
# .text:495A5E 66 90                                   xchg    ax, ax
# .text:495A60 E8 5B 0F FD FF                          call    runtime_slicebytetostring
# .text:495A65 48 83 C4 30                             add     rsp, 30h
# .text:495A69 5D                                      pop     rbp
# .text:495A6A C3                                      retn

V21_V23_SEED_EPILOGUE_PATTERN = rb'\x48\x8b[\S\s]\x48\x8b[\S\s]{2}\x31\xC0[\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48[\x81\x83][\S\s]{2,5}\x5D\xC3'
```

Old:
``` python
# 48 8B 19                mov     rbx, [rcx]                      ; a1
# 48 8B 49 08             mov     rcx, [rcx+8]                    ; a2
# 31 C0                   xor     eax, eax
# E8 DB D7 8F FF          call    runtime_slicebytetostring
# 48 8B 6C 24 30          mov     rbp, [rsp+38h+var_8]
# 48 83 C4 38             add     rsp, 38h
# C3                      retn

OLD_SEED_EPILOGUE_PATTERN = rb'\x48\x8b[\S\s]\x48\x8b[\S\s]{2}\x31\xC0[\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48\x8b[\S\s]{3,6}\x48[\x81\x83][\S\s]{2,5}\xC3'
```

# String Decrypting Subroutine's Regex Patterns (x86)

## Prologue Pattern 

String decryption prologue (same for all 3 decryption types)

``` python
# .text:00477040 8B 0D 24 A7 63 00       mov     ecx, dword_63A724
# .text:00477046 64 8B 09                mov     ecx, fs:[ecx]
# .text:00477049 8B 09                   mov     ecx, [ecx]
# .text:0047704B 3B 61 08                cmp     esp, [ecx+8]
# .text:0047704E 0F 86 2E 02 00 00       jbe     loc_477282
# .text:00477054 83 EC 20                sub     esp, 20h

PROLOGUE_PATTERN = rb'\x8B\x0D[\S\s]{4}\x64\x8B\x09\x8b\x09\x3B\x61\x08[\x0F\x76]'
```

## Stack Epilogue

V1.21 -> 1.23
``` python
# .text:004746BE 89 44 24 04             mov     [esp+24h+var_20], eax           ; int
# .text:004746C2 C7 44 24 08 0C 00 00 00 mov     [esp+24h+var_1C], 0Ch           ; int
# .text:004746CA E8 61 34 FF FF          call    runtime_slicebytetostring
# .text:004746CF 8B 44 24 0C             mov     eax, [esp+24h+var_18]
# .text:004746D3 8B 4C 24 10             mov     ecx, [esp+24h+var_14]
# .text:004746D7 89 44 24 28             mov     dword ptr [esp+24h+arg_0], eax
# .text:004746DB 89 4C 24 2C             mov     dword ptr [esp+24h+arg_0+4], ecx
# .text:004746DF 83 C4 24                add     esp, 24h
# .text:004746E2 C3                      retn

V21_V23_STACK_EPILOGUE_PATTERN = rb'\x89\x44\x24\x04\xC7\x44\x24\x08[\S\s]{4}\xE8[\S\s]{4}\x8B\x44\x24\x0c\x8B\x4C\x24\x10\x89\x44\x24[\S\s]\x89\x4C\x24[\S\s]\x83\xC4[\S\s]\xC3'
```

## Split Epilogue

V1.21 -> 1.23
```python
# .text:00510F27 89 6C 24 04             mov     [esp+40h+var_3C], ebp           ; int
# .text:00510F2B 89 74 24 08             mov     [esp+40h+var_38], esi           ; int
# .text:00510F2F E8 FC 6B F5 FF          call    runtime_slicebytetostring
# .text:00510F34 8B 44 24 0C             mov     eax, [esp+40h+var_34]
# .text:00510F38 8B 4C 24 10             mov     ecx, [esp+40h+var_30]
# .text:00510F3C 89 44 24 44             mov     dword ptr [esp+40h+arg_0], eax
# .text:00510F40 89 4C 24 48             mov     dword ptr [esp+40h+arg_0+4], ecx
# .text:00510F44 83 C4 40                add     esp, 40h
# .text:00510F47 C3                      retn

V21_V23_SPLIT_EPILOGUE_PATTERN = rb'\x89\x6C\x24\x04\x89\x74\x24\x08\xE8[\S\s]{4}\x8B\x44\x24\x0c\x8B\x4C\x24\x10\x89\x44\x24[\S\s]\x89\x4C\x24[\S\s]\x83\xC4[\S\s]\xC3'
```

## Seed Epilogue

V1.21 -> 1.23
```python
# .text:00474531 89 4C 24 04             mov     [esp+20h+var_1C], ecx           ; int
# .text:00474535 89 44 24 08             mov     [esp+20h+var_18], eax           ; int
# .text:00474539 E8 F2 35 FF FF          call    runtime_slicebytetostring
# .text:0047453E 8B 44 24 0C             mov     eax, [esp+20h+var_14]
# .text:00474542 8B 4C 24 10             mov     ecx, [esp+20h+var_10]
# .text:00474546 89 44 24 24             mov     dword ptr [esp+20h+arg_0], eax
# .text:0047454A 89 4C 24 28             mov     dword ptr [esp+20h+arg_0+4], ecx
# .text:0047454E 83 C4 20                add     esp, 20h
# .text:00474551 C3                      retn

V21_V23_SEED_EPILOGUE_PATTERN = rb'\x89\x4C\x24\x04\x89\x44\x24\x08\xE8[\S\s]{4}\x8B\x44\x24\x0c\x8B\x4C\x24\x10\x89\x44\x24[\S\s]\x89\x4C\x24[\S\s]\x83\xC4[\S\s]\xC3'
```