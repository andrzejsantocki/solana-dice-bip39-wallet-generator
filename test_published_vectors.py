import hashlib
import unittest
from unittest.mock import patch

import generate_wallet as gw


class PublishedVectorTests(unittest.TestCase):
    def test_bip39_official_vector_entropy_to_mnemonic_and_seed(self):
        entropy = bytes.fromhex('00000000000000000000000000000000')
        words = gw.Mnemonic('english').to_mnemonic(entropy)
        self.assertEqual(words, 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')
        seed = gw.Mnemonic('english').to_seed(words, 'TREZOR').hex()
        self.assertEqual(seed, 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553'
                               '1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04')

    def test_bip32_vector_1_master_and_m_0h_1_private_chaincode_public(self):
        seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        k, c = gw.bip32_master(seed)
        self.assertEqual(k.hex(), 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35')
        self.assertEqual(c.hex(), '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508')
        self.assertEqual(gw.compress_point(gw.point_from_priv(int.from_bytes(k, 'big'))).hex(),
                         '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2')
        k, c = gw.bip32_ckd_priv(k, c, gw.H(0))
        k, c = gw.bip32_ckd_priv(k, c, 1)
        self.assertEqual(k.hex(), '3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368')
        self.assertEqual(c.hex(), '2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19')
        self.assertEqual(gw.compress_point(gw.point_from_priv(int.from_bytes(k, 'big'))).hex(),
                         '03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c')

    def test_end_to_end_solana_bip39_to_phantom_address_golden_vector(self):
        # Independent public Solana/BIP44 vector for the standard BIP39 test mnemonic.
        # Path: m/44'/501'/0'/0' (Phantom/Solflare common)
        words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        seed = gw.Mnemonic('english').to_seed(words, '')
        address, _secret32 = gw.sol_from_seed(seed, (44, 501, 0, 0))
        self.assertEqual(address, 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk')

    def test_slip0010_ed25519_vector_1_master_and_m_0h(self):
        seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        k, c = gw.slip10_ed25519_master(seed)
        self.assertEqual(k.hex(), '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7')
        self.assertEqual(c.hex(), '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb')
        self.assertEqual((b'\x00' + gw.nacl.signing.SigningKey(k).verify_key.encode()).hex(),
                         '00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed')
        k, c = gw.slip10_ed25519_ckd(k, c, 0)
        self.assertEqual(k.hex(), '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3')
        self.assertEqual(c.hex(), '8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69')
        self.assertEqual((b'\x00' + gw.nacl.signing.SigningKey(k).verify_key.encode()).hex(),
                         '008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c')

    def test_base58_and_ripemd160_known_vectors_including_fallback(self):
        self.assertEqual(gw.b58encode(b'\x00\x00\x01'), '112')
        self.assertEqual(gw.b58check_encode(b'\x00' + bytes(20)), '1111111111111111111114oLvT2')
        self.assertEqual(gw.ripemd160(b'').hex(), '9c1185a5c5e9fc54612808977ee8f548b2258d31')
        real_new = hashlib.new
        def fake_new(name, *args, **kwargs):
            if name == 'ripemd160':
                raise ValueError('disabled')
            return real_new(name, *args, **kwargs)
        with patch('generate_wallet.hashlib.new', fake_new):
            self.assertEqual(gw.ripemd160(b'').hex(), '9c1185a5c5e9fc54612808977ee8f548b2258d31')

    def test_hash_roll_quality_does_not_emit_von_neumann_pair_warning(self):
        rolls = [1, 2, 3, 4, 5, 6] * 25
        q = gw.analyze_roll_quality(rolls, None, None)
        self.assertNotIn('insufficient unbiased bit yield', q['warnings'])


if __name__ == '__main__':
    unittest.main()
