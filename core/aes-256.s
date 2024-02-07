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
.equ R11, 176
.equ R12, 192
.equ R13, 208
.equ R14, 224

.section .text

.global AES256_KeySchedule
.global AES256_KeySchedule_Inv

.macro aeskeyexpand temp, prev, curr
    pshufd $0xff, \curr, \curr
    shufps $0x40, \prev, \temp
    pxor \temp, \prev
    shufps $0x98, \prev, \temp
    pxor \temp, \prev
    pxor \prev, \curr
.endm

.macro aeskeyexpand_e temp, prev, curr
    pshufd $0xaa, \curr, \curr
    shufps $0x40, \prev, \temp
    pxor \temp, \prev
    shufps $0x98, \prev, \temp
    pxor \temp, \prev
    pxor \prev, \curr
.endm

#
# AES Key Schedule
#
# Expands the given key into 14 separate round keys, used by
# encryption functions (those that do not generate round keys in the process)
#
# Parameters:
#   %rdi - address of a memory area 240 bytes long, with the initial 32 bytes
#          set to represent the input key.
#
# Variables:
#   %xmm0...%xmm14 - round keys
#   %xmm15         - intermediate value utilized by the key expansion macros
AES256_KeySchedule:
    pxor           %xmm15, %xmm15
    movups         (%rdi), %xmm0
    movups       R1(%rdi), %xmm1

    aeskeygenassist  $RC1, %xmm1, %xmm2
    aeskeyexpand   %xmm15, %xmm0, %xmm2
    movups         %xmm2,  R2(%rdi)

    aeskeygenassist  $RC1, %xmm2, %xmm3
    aeskeyexpand_e %xmm15, %xmm1, %xmm3
    movups         %xmm3,  R3(%rdi)

    aeskeygenassist  $RC2, %xmm3, %xmm4
    aeskeyexpand   %xmm15, %xmm2, %xmm4
    movups         %xmm4,  R4(%rdi)

    aeskeygenassist  $RC2, %xmm4, %xmm5
    aeskeyexpand_e %xmm15, %xmm3, %xmm5
    movups         %xmm5,  R5(%rdi)

    aeskeygenassist  $RC3, %xmm5, %xmm6
    aeskeyexpand   %xmm15, %xmm4, %xmm6
    movups         %xmm6,  R6(%rdi)

    aeskeygenassist  $RC3, %xmm6, %xmm7
    aeskeyexpand_e %xmm15, %xmm5, %xmm7
    movups         %xmm7,  R7(%rdi)

    aeskeygenassist  $RC4, %xmm7, %xmm8
    aeskeyexpand   %xmm15, %xmm6, %xmm8
    movups         %xmm8,  R8(%rdi)

    aeskeygenassist  $RC4, %xmm8, %xmm9
    aeskeyexpand_e %xmm15, %xmm7, %xmm9
    movups         %xmm9,  R9(%rdi)

    aeskeygenassist  $RC5, %xmm9, %xmm10
    aeskeyexpand   %xmm15, %xmm8, %xmm10
    movups         %xmm10, R10(%rdi)

    aeskeygenassist  $RC5, %xmm10, %xmm11
    aeskeyexpand_e %xmm15, %xmm9,  %xmm11
    movups         %xmm11, R11(%rdi)

    aeskeygenassist  $RC6, %xmm11, %xmm12
    aeskeyexpand   %xmm15, %xmm10, %xmm12
    movups         %xmm12, R12(%rdi)

    aeskeygenassist  $RC6, %xmm12, %xmm13
    aeskeyexpand_e %xmm15, %xmm11, %xmm13
    movups         %xmm13, R13(%rdi)

    aeskeygenassist  $RC7, %xmm13, %xmm14
    aeskeyexpand   %xmm15, %xmm12, %xmm14
    movups         %xmm14, R14(%rdi)

    ret

#
# AES Inverse Key Schedule
#
# Expands the given key into 14 separate round keys, used by
# decryption functions (those that do not generate round keys in the process)
#
# Parameters:
#   %rdi - address of a memory area 240 bytes long, with the initial 32 bytes
#          set to represent the input key.
#
# Variables:
#   %xmm0...%xmm14 - round keys
#   %xmm15         - intermediate value utilized by the key expansion macros
AES256_KeySchedule_Inv:
    pxor           %xmm15, %xmm15
    movups         (%rdi), %xmm0
    movups       R1(%rdi), %xmm1

    aesimc          %xmm1, %xmm2
    movups          %xmm2, R1(%rdi)

    aeskeygenassist  $RC1, %xmm1, %xmm2
    aeskeyexpand   %xmm15, %xmm0, %xmm2
    aesimc         %xmm2,  %xmm0
    movups         %xmm0,  R2(%rdi)

    aeskeygenassist  $RC1, %xmm2, %xmm3
    aeskeyexpand_e %xmm15, %xmm1, %xmm3
    aesimc         %xmm3,  %xmm1
    movups         %xmm1,  R3(%rdi)

    aeskeygenassist  $RC2, %xmm3, %xmm4
    aeskeyexpand   %xmm15, %xmm2, %xmm4
    aesimc         %xmm4,  %xmm2
    movups         %xmm2,  R4(%rdi)

    aeskeygenassist  $RC2, %xmm4, %xmm5
    aeskeyexpand_e %xmm15, %xmm3, %xmm5
    aesimc         %xmm5,  %xmm3
    movups         %xmm3,  R5(%rdi)

    aeskeygenassist  $RC3, %xmm5, %xmm6
    aeskeyexpand   %xmm15, %xmm4, %xmm6
    aesimc         %xmm6,  %xmm4
    movups         %xmm4,  R6(%rdi)

    aeskeygenassist  $RC3, %xmm6, %xmm7
    aeskeyexpand_e %xmm15, %xmm5, %xmm7
    aesimc         %xmm7,  %xmm5
    movups         %xmm5,  R7(%rdi)

    aeskeygenassist  $RC4, %xmm7, %xmm8
    aeskeyexpand   %xmm15, %xmm6, %xmm8
    aesimc         %xmm8,  %xmm6
    movups         %xmm6,  R8(%rdi)

    aeskeygenassist  $RC4, %xmm8, %xmm9
    aeskeyexpand_e %xmm15, %xmm7, %xmm9
    aesimc         %xmm9,  %xmm7
    movups         %xmm7,  R9(%rdi)

    aeskeygenassist  $RC5, %xmm9, %xmm10
    aeskeyexpand   %xmm15, %xmm8, %xmm10
    aesimc         %xmm10, %xmm8
    movups         %xmm8,  R10(%rdi)

    aeskeygenassist  $RC5, %xmm10, %xmm11
    aeskeyexpand_e %xmm15, %xmm9,  %xmm11
    aesimc         %xmm11, %xmm9
    movups         %xmm9,  R11(%rdi)

    aeskeygenassist  $RC6, %xmm11, %xmm12
    aeskeyexpand   %xmm15, %xmm10, %xmm12
    aesimc         %xmm12, %xmm10
    movups         %xmm10, R12(%rdi)

    aeskeygenassist  $RC6, %xmm12, %xmm13
    aeskeyexpand_e %xmm15, %xmm11, %xmm13
    aesimc         %xmm13, %xmm11
    movups         %xmm11, R13(%rdi)

    aeskeygenassist  $RC7, %xmm13, %xmm14
    aeskeyexpand   %xmm15, %xmm12, %xmm14
    movups         %xmm14, R14(%rdi)

    ret
