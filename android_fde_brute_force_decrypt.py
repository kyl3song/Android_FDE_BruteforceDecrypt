# -*- coding: utf-8 -*-
# @Author: Kyle Song
# @Date:   2021-05-02 08:24:31
# @Last Modified by:   KyleSong

from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import scrypt
import hashlib
import struct
import os
import itertools


KDF_PBKDF = 1
KDF_SCRYPT = 2
IV_LEN_BYTES = 16
SECTOR_SIZE = 512

# Sector is 512 bytes, block for essiv is 16 bytes.
# Encrypted salt-sector initialization vector (ESSIV)
# https://en.wikipedia.org/wiki/Disk_encryption_theory#Encrypted_salt-sector_initialization_vector_.28ESSIV.29
FIRST_BLOCK_FOR_ESSIV = b'\x00' * 16
FIRST_BLANK_SECTOR = b'\x00' * 512

PIN_RANGE = "0123456789"
PIN_MAX_DIGITS = 6

class CryptoFooter:

    def __init__(self) -> None:
        pass

    def unpack(self, cf):
        '''
        #define MAX_CRYPTO_TYPE_NAME_LEN 64
        #define MAX_KEY_LEN 48
        #define SALT_LEN 16

        struct crypt_mnt_ftr {
        __le32 magic;         /* See above */
        __le16 major_version;
        __le16 minor_version;
        __le32 ftr_size;      /* in bytes, not including key following */
        __le32 flags;         /* See above */
        __le32 keysize;       /* in bytes */
        __le32 crypt_type;    /* how master_key is encrypted. Must be a
                                * CRYPT_TYPE_XXX value */
        __le64 fs_size;       /* Size of the encrypted fs, in 512 byte sectors */
        __le32 failed_decrypt_count; /* count of # of failed attempts to decrypt and
                                        mount, set to 0 on successful mount */
        unsigned char crypto_type_name[MAX_CRYPTO_TYPE_NAME_LEN]; /* The type of encryption
                                                                    needed to decrypt this
                                                                    partition, null terminated */
        __le32 spare2;        /* ignored */
        unsigned char master_key[MAX_KEY_LEN]; /* The encrypted key for decrypting the filesystem */
        unsigned char salt[SALT_LEN];   /* The salt used for this encryption */
        __le64 persist_data_offset[2];  /* Absolute offset to both copies of crypt_persist_data
                                        * on device with that info, either the footer of the
                                        * real_blkdevice or the metadata partition. */
        __le32 persist_data_size;       /* The number of bytes allocated to each copy of the
                                        * persistent data table*/
        __le8  kdf_type; /* The key derivation function used. */
        /* scrypt parameters. See www.tarsnap.com/scrypt/scrypt.pdf */
        __le8  N_factor; /* (1 << N) */
        __le8  r_factor; /* (1 << r) */
        __le8  p_factor; /* (1 << p) */
        __le64 encrypted_upto; /* If we are in state CRYPT_ENCRYPTION_IN_PROGRESS and
                                    we have to stop (e.g. power low) this is the last
                                    encrypted 512 byte sector.*/
        __le8  hash_first_block[SHA256_DIGEST_LENGTH]; /* When CRYPT_ENCRYPTION_IN_PROGRESS
                                                            set, hash of first block, used
                                                            to validate before continuing*/
        /* ============ Stripped ============ */
        '''

        (self.ftr_magic, self.major_version, self.minor_version, self.ftr_size, self.flags,
         self.keysize, self.crypto_type, self.fs_size, self.failed_decrypt_count, self.crypto_type_name,
         self.spare2, self.master_key, self.salt, self.persist_data_offset_1, self.persist_data_offset_2,
         self.persist_data_size, self.kdf_type, self.N, self.r, self.p) \
        = struct.unpack("<" + "L H H L L L L Q L 64s L 48s 16s Q Q L B B B B", cf[:192])

    def dump(self):
        print("Android FDE crypto footer")
        print('-------------------------')
        print(f'Magic              : 0x{self.ftr_magic:8X}')
        print(f'Major Version      : {self.major_version}')
        print(f'Minor Version      : {self.minor_version}')
        print(f'Footer Size        : {self.ftr_size:,} bytes')
        print(f'Flags              : 0x{self.flags:08X}')
        print(f'Key Size           : {self.keysize} ({self.keysize * 8} bits)')

        if self.crypto_type == 0:
            self.crypt_with = "PASSWORD: Master_key is encrypted with a password"
        elif self.crypto_type == 1:
            self.crypt_with = "DEFAULT : Master_key is encrypted with 'default_password'"
        elif self.crypto_type == 2:
            self.crypt_with = "PATTERN : Master_key is encrypted with PATTERN"
        elif self.crypto_type == 3:
            self.crypt_with = "PIN : Master_key is encrypted with PIN"
        print(f'Crypto Type        : {self.crypto_type} ({self.crypt_with})')
        print(f'Encrypted Size(sec): {self.fs_size:,} Sector ({self.fs_size * SECTOR_SIZE:,} bytes)')
        print(f'Failed Decrypts    : {self.failed_decrypt_count}')

        self.crypto_type_name = str(self.crypto_type_name).replace('\\x00','')
        print(f'Crypto Type Name   : {self.crypto_type_name}')

        self.master_key = self.master_key[:self.keysize]
        print(f'Encrypted Key      : 0x{self.master_key.hex()}')
        print(f'Salt               : 0x{self.salt.hex()}')

        if self.kdf_type == 1:
            self.kdf = 'KDF_PBKDF2'
        elif self.kdf_type == 2:
            self.kdf = 'KDF_SCRYPT'
        else:
            self.kdf = 'SCRYPT_KEYMASTER'
        print(f'KDF Type           : {self.kdf_type} ({self.kdf})')

        print(f'N_factor           : {self.N} (1 << {self.N})')
        print(f'r_factor           : {self.r} (1 << {self.r})')
        print(f'p_factor           : {self.p} (1 << {self.p})')
        print('-------------------------')

def get_crypto_footer_info(data):
    cf = CryptoFooter()
    cf.unpack(data)
    cf.dump()

    return cf


def decrypt_data(data, cf, password):
    # if key length in CryptoFooter is 16, it outputs 32bytes as derived | key: 16 bytes, iv: 16 bytes
    # if key length in CryptoFooter is 32, it outputs 48bytes as derived | key: 32 bytes, iv: 16 bytes
    derived = scrypt(password.encode(), cf.salt, cf.keysize+IV_LEN_BYTES, 1<<cf.N, 1<<cf.r, 1<<cf.p)
    key = derived[:cf.keysize]
    iv = derived[cf.keysize:]

    # do the decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec_dek = cipher.decrypt(cf.master_key)
    dec_dek_sha256 = hashlib.sha256(dec_dek).digest()

    cipher = AES.new(dec_dek_sha256, AES.MODE_ECB)
    essiv = cipher.encrypt(FIRST_BLOCK_FOR_ESSIV)

    cipher = AES.new(dec_dek, AES.MODE_CBC, essiv)
    dec_data = cipher.decrypt(data)

    return dec_dek, dec_data


def brute_force_pin(encrypted_first_sector, cf, max_digits=4, known_user_pwd=None):
    print('Trying to Bruteforce Password... please wait')

    if known_user_pwd == None:
        for i in itertools.product(PIN_RANGE, repeat=max_digits):
            pwd_try = ''.join(i)
            print(f'[+] Trying Password: {pwd_try}')

            if cf.kdf == 'KDF_SCRYPT':
                dec_dek, dec_data = decrypt_data(encrypted_first_sector, cf, pwd_try)
                if dec_data == FIRST_BLANK_SECTOR:
                    return True, [pwd_try, dec_dek, cf]
            else:
                raise ("Unknown KDF or Not Implemented yet")
        print("[*] Cannot find PIN")
        return False, None, None
    else:
        if cf.kdf == 'KDF_SCRYPT':
            # Decrypt first sector of FDE partition
            dec_dek, dec_data = decrypt_data(encrypted_first_sector, cf, known_user_pwd)
            if dec_data == FIRST_BLANK_SECTOR:
                return True, [known_user_pwd, dec_dek]


def decrypt_fde(encrypted_file, dek, decrypted_file):
    enc_file_size = os.path.getsize(encrypted_file)
    fh_enc_file = open(encrypted_file, mode='rb')
    fh_dec_file = open(decrypted_file, mode='ab')

    count = 0
    decrypt_processed = 0

    while True:
        data = fh_enc_file.read(SECTOR_SIZE)

        if data == b'':
            print("[*] End of file, break..")
            break

        dek_sha256 = hashlib.sha256(dek).digest()
        cipher = AES.new(dek_sha256, AES.MODE_ECB)

        ''' pack example
        struc.pack("<2Q", 0, 0)
        b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
        struc.pack("<2Q", 1, 0)
        b'\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
        '''
        sector_iv = struct.pack("<2Q", count, 0)
        essiv = cipher.encrypt(sector_iv)
        cipher = AES.new(dek, AES.MODE_CBC, essiv)
        dec_data = cipher.decrypt(data)

        fh_dec_file.write(dec_data)

        count += 1
        decrypt_processed += SECTOR_SIZE

        # Prints current status per 1000 iter
        if count % 1000 == 0:
            print(f"[+] Decrypt FDE Processed ({decrypt_processed:,}/{enc_file_size:,} Bytes) - {dec_data[:16]}")
    
    fh_enc_file.close()
    fh_dec_file.close()


def main():
    # Reads crypto footer file
    crypto_footer_file = 'crypto_footer.dat'
    encrypted_file = 'FDE_partition22.dd'
    decrypted_file = 'FDE_partition22_decrypted.dd'

    with open(crypto_footer_file, mode='rb') as cf:
        footer_data = cf.read()

    with open(encrypted_file, mode='rb') as enc_data:
        encrypted_first_sector = enc_data.read(512)

    cf = get_crypto_footer_info(footer_data)

    # 1 - DEFAULT : Master_key is encrypted with 'default_password'
    known_user_pwd = 'default_password' if cf.crypto_type == 1 else None

    # Returns True/False, User Password, Decrypted DEK, Crypto Footer
    is_brute_forced, val = brute_force_pin(encrypted_first_sector, cf, PIN_MAX_DIGITS, known_user_pwd)

    if is_brute_forced == True:
        pwd, dec_dek = val
        print(f"[*] USER PASSWORD Found!: {pwd}")
        print(f"[*] Disk Encryption Key(DEK) Found!: {dec_dek.hex()}")
        val = input(f"[*] Do you want to decrypt FDE partition({encrypted_file})(y/n): ")
        if (val == 'Y') or (val == 'y'):
            decrypt_fde(encrypted_file, dec_dek, decrypted_file)
   


if __name__ == "__main__":
    main()
