.include "core/rcon.s"

.section .bss
.section .data

.equ R1,  16
.equ R2,  32
.equ R3,  48
.equ R4,  64
.equ R5,  80
.equ R6,  96
.equ R7,  112
.equ R8,  128
.equ R9,  144
.equ R10, 160

.section .text

.global AES128_KeySchedule
.global AES128_KeySchedule_Inv

.global AES128_EncryptBlock_P
.global AES128_DecryptBlock_P

.macro aeskeyexpand temp, prev, curr
    pshufd $0xff, \curr, \curr
    shufps $0x40, \prev, \temp
    pxor \temp, \prev
    shufps $0x98, \prev, \temp
    pxor \temp, \prev
    pxor \curr, \prev
.endm

#
# AES Key Schedule
#
# Expands the given key into 10 separate round keys, used by
# encryption functions (those that do not generate round keys in the process)
#
# Parameters:
#   %rdi - address of a memory area 176 bytes long, with the initial 16 bytes
#          set to represent the input key.
#
# Variables:
#   %xmm0 - intermediate value utilized by the key expansion macro
#   %xmm1 - key computed in the previous round (initially represents the input key)
#   %xmm2 - result of the aeskeygenassist instruction
AES128_KeySchedule:
    pxor    %xmm0, %xmm0
    movups (%rdi), %xmm1

    aeskeygenassist  $RC1, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    movups          %xmm1, R1(%rdi)

    aeskeygenassist  $RC2, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    movups          %xmm1, R2(%rdi)

    aeskeygenassist  $RC3, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    movups          %xmm1, R3(%rdi)

    aeskeygenassist  $RC4, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    movups          %xmm1, R4(%rdi)

    aeskeygenassist  $RC5, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    movups          %xmm1, R5(%rdi)

    aeskeygenassist  $RC6, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    movups          %xmm1, R6(%rdi)

    aeskeygenassist  $RC7, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    movups          %xmm1, R7(%rdi)

    aeskeygenassist  $RC8, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    movups          %xmm1, R8(%rdi)

    aeskeygenassist  $RC9, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    movups          %xmm1, R9(%rdi)

    aeskeygenassist $RC10, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    movups          %xmm1, R10(%rdi)

    ret

#
# AES Inverse Key Schedule
#
# Expands the given key into 10 separate round keys, used by
# decryption functions (those that do not generate round keys in the process)
#
# Parameters:
#   %rdi - address of a memory area 176 bytes long, with the initial 16 bytes
#          set to represent the input key.
#
# Variables:
#   %xmm0 - intermediate value utilized by the key expansion macro
#   %xmm1 - key computed in the previous round (initially represents the input key)
#   %xmm2 - result of the aeskeygenassist and aesimc instruction
#   %xmm3 - result of the aesimc instruction
AES128_KeySchedule_Inv:
    pxor    %xmm0, %xmm0
    movups (%rdi), %xmm1

    aeskeygenassist  $RC1, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    aesimc          %xmm1, %xmm3
    movups          %xmm3, R1(%rdi)

    aeskeygenassist  $RC2, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    aesimc          %xmm1, %xmm3
    movups          %xmm3, R2(%rdi)

    aeskeygenassist  $RC3, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    aesimc          %xmm1, %xmm3
    movups          %xmm3, R3(%rdi)

    aeskeygenassist  $RC4, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    aesimc          %xmm1, %xmm3
    movups          %xmm3, R4(%rdi)

    aeskeygenassist  $RC5, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    aesimc          %xmm1, %xmm3
    movups          %xmm3, R5(%rdi)

    aeskeygenassist  $RC6, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    aesimc          %xmm1, %xmm3
    movups          %xmm3, R6(%rdi)

    aeskeygenassist  $RC7, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    aesimc          %xmm1, %xmm3
    movups          %xmm3, R7(%rdi)

    aeskeygenassist  $RC8, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    aesimc          %xmm1, %xmm3
    movups          %xmm3, R8(%rdi)

    aeskeygenassist  $RC9, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    aesimc          %xmm1, %xmm3
    movups          %xmm3, R9(%rdi)

    aeskeygenassist $RC10, %xmm1, %xmm2
    aeskeyexpand    %xmm0, %xmm1, %xmm2
    movups          %xmm1, R10(%rdi)

    ret

#
# AES Block Encryption
#
# Encrypts a single 128-bit block of data using a set of precomputed keys.
#
# Parameters:
#   %rdi - memory address of the output buffer that is at least 16 bytes long
#   %rsi - memory address of the input data block
#   %rdx - memory address where round keys are stored
AES128_EncryptBlock_P:
    movups        (%rsi), %xmm0
    pxor          (%rdx), %xmm0
    aesenc      R1(%rdx), %xmm0
    aesenc      R2(%rdx), %xmm0
    aesenc      R3(%rdx), %xmm0
    aesenc      R4(%rdx), %xmm0
    aesenc      R5(%rdx), %xmm0
    aesenc      R6(%rdx), %xmm0
    aesenc      R7(%rdx), %xmm0
    aesenc      R8(%rdx), %xmm0
    aesenc      R9(%rdx), %xmm0
    aesenclast R10(%rdx), %xmm0
    movups         %xmm0, (%rdi)
    ret

#
# AES Block Decryption
#
# Decrypts a single 128-bit block of data using a set of precomputed keys.
#
# Parameters:
#   %rdi - memory address of the output buffer that is at least 16 bytes long
#   %rsi - memory address of the input data block
#   %rdx - memory address where round keys are stored
AES128_DecryptBlock_P:
    movups        (%rsi), %xmm0
    pxor       R10(%rdx), %xmm0
    aesdec      R9(%rdx), %xmm0
    aesdec      R8(%rdx), %xmm0
    aesdec      R7(%rdx), %xmm0
    aesdec      R6(%rdx), %xmm0
    aesdec      R5(%rdx), %xmm0
    aesdec      R4(%rdx), %xmm0
    aesdec      R3(%rdx), %xmm0
    aesdec      R2(%rdx), %xmm0
    aesdec      R1(%rdx), %xmm0
    aesdeclast    (%rdx), %xmm0
    movups         %xmm0, (%rdi)
    ret
