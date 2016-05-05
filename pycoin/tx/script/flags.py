
VERIFY_NONE = 0

# Evaluate P2SH subscripts (softfork safe, BIP16).
VERIFY_P2SH = (1 << 0)

# Passing a non-strict-DER signature or one with undefined hashtype to a checksig
# operation causes script failure. Evaluating a pubkey that is not (0x04 + 64 bytes)
# or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
# (softfork safe, but not used or intended as a consensus rule).
VERIFY_STRICTENC = (1 << 1)

# Passing a non-strict-DER signature to a checksig operation causes script failure
# (softfork safe, BIP62 rule 1)
VERIFY_DERSIG = (1 << 2)

# Passing a non-strict-DER signature or one with S > order/2 to a checksig operation
# causes script failure (softfork safe, BIP62 rule 5).
VERIFY_LOW_S = (1 << 3)

# verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe,
# BIP62 rule 7).
VERIFY_NULLDUMMY = (1 << 4)

# Using a non-push operator in the scriptSig causes script failure (softfork safe,
# BIP62 rule 2).
VERIFY_SIGPUSHONLY = (1 << 5)

# Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where
# possible, direct pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for
# anything larger). Evaluating any other push causes the script to fail (BIP62 rule 3).
# In addition, whenever a stack element is interpreted as a number, it must be of minimal
# length (BIP62 rule 4). (softfork safe)
VERIFY_MINIMALDATA = (1 << 6)

# Discourage use of NOPs reserved for upgrades (NOP1-10)
# Provided so that nodes can avoid accepting or mining transactions
# containing executed NOP's whose meaning may change after a soft-fork,
# thus rendering the script invalid; with this flag set executing
# discouraged NOPs fails the script. This verification flag will never be
# a mandatory flag applied to scripts in a block. NOPs that are not
# executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1 << 7)

VERIFY_CLEANSTACK = (1 << 8)

# Verify CHECKLOCKTIMEVERIFY
#
# See BIP65 for details.
VERIFY_CHECKLOCKTIMEVERIFY = (1 << 9)
