#
# Round Constants
#
# The round constant `rcon` for round i of the key expansion
# is a 32-bit word:
#   rcon = [rc 00 00 00]
#
# The following code outlines the rc values associated with each round.
#
# For additional information, refer to:
#   https://en.wikipedia.org/wiki/AES_key_schedule
#
# ---

.section .data

.equ RC1,  0x01
.equ RC2,  0x02
.equ RC3,  0x04
.equ RC4,  0x08
.equ RC5,  0x10
.equ RC6,  0x20
.equ RC7,  0x40
.equ RC8,  0x80
.equ RC9,  0x1B
.equ RC10, 0x36
