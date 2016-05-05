#!/usr/bin/env python

##
#    Copyright (C) 2016 - Edilson Osorio Junior
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    HOW IT WORKS
#
#    bitEncrypt is a Proof-of-Concept for encrypting messages using the
#    private/public bitcoin key pair.
#    
#    From destination wallet you must to provide:
#    - To encrypt a message, you need the uncompressed public key
#    - To decrypt a message, you need the private key in wif, hex or uncompressed
#    In this example we extract the uncompressed public key from the private key
#    provided.
#    
#    The secret would be from blockchain.info (hex) or from bitcoin core dumpprivkey (wif)
#    If you dont own the dest wallet, the public key can be found just if it has 
#    any transaction. 
#    Ex.: https://blockchain.info/q/pubkeyaddr/1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY
#    
#    If already you have the private and public keys, just add them 
#    manually to privkey_uncompressed and pubkey_uncompressed vars.
##

import pyelliptic
import re
from pyelliptic import arithmetic
from binascii import hexlify, unhexlify
from pycoin.key.Key import Key
from pycoin import encoding
from pycoin.ecdsa import secp256k1

message = "Encrypt/Decrypt this text using Bitcoin Public Private key pair"
secret = "L5Se36mXekGsMDCxLausHsfaFn1KRaRV7hrJNuYmoyEJ4M5GxfLV"

##
# Test and define what kind of secret exponent was provided
##

SEC_RE = re.compile(r"^(0[23][0-9a-fA-F]{64})|(04[0-9a-fA-F]{128})$")

def parse_as_number(s):
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return int(s, 16)
    except ValueError:
        pass

def parse_as_secret_exponent(s):
    v = parse_as_number(s)
    if v and v < secp256k1._r:
        return v

secret_exponent = parse_as_secret_exponent(secret)
if secret_exponent:
    privkey = Key(secret_exponent=secret_exponent)

if SEC_RE.match(secret):
    privkey = Key.from_sec(unhexlify(secret))
else:
    try: 
        privkey = Key.from_text(secret)
    except encoding.EncodingError:
        pass
    
# Define vars automatically from privkey (could be manually, if you had the values)
privkey_uncompressed = '%x' % privkey.secret_exponent()
pubkey_uncompressed = hexlify(privkey.sec(use_uncompressed=True))

##
# Prepare pubkey for encrypting
##

pubkey_bin_tmp = arithmetic.changebase(pubkey_uncompressed[2:], 16, 256, minlen=64)
pubkey_bin = '\x02\xca\x00 '+ pubkey_bin_tmp[:32] + '\x00 ' + pubkey_bin_tmp[32:]

# Optionally you can use unhexlify, but need to add '\x20' after '\x00'
#pubkey_bin_tmp = unhexlify(pubkey_uncompressed)
#pubkey_bin = '\x02\xca\x00\x20' + pubkey_bin_tmp[1:-32] + '\x00\x20' + pubkey_bin_tmp[-32:]

##
# Prepare private key for decrypting
##

# Private Key to Bin
privkey_bin = '\x02\xca\x00\x20' + arithmetic.changebase(privkey_uncompressed, 16, 256, minlen=32)

# Optionally you can use unhexlify
#privkey_bin = '\x02\xca\x00\x20' + unhexlify(privkey_uncompressed)

##
# Outputs
##
print "Encrypt for wallet: %s" % privkey.address(use_uncompressed=False)
print "Uncompressed Hex Pubkey: %s" % pubkey_uncompressed
print "Message: ", message
print "\n"

encrypted = pyelliptic.ECC(curve='secp256k1').encrypt(message, pubkey_bin)
print "Hex Crypto Message: ", hexlify(encrypted)

decrypted = pyelliptic.ECC(curve='secp256k1', privkey=privkey_bin, pubkey=pubkey_bin).decrypt(encrypted)
print "Decrypted message: ", decrypted
