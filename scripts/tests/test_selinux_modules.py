"""Synthetic pure store-evidence tests; no commands or policy observation."""
from dataclasses import FrozenInstanceError
import hashlib
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'packaging/selinux'))
import qshd_selinux_modules as model


class ModuleTests(unittest.TestCase):
    def test_padded_listing_and_immutable_selection(self):
        entries=model.parse_full_listing(b'100 example-base  cil          \n400 qshd          pp           \n200 sample_other pp disabled \n')
        owned=model.select_owned(entries)
        self.assertEqual((owned.priority,owned.name,owned.language,owned.enabled),(400,'qshd','pp',True))
        self.assertFalse(entries[2].enabled)
        with self.assertRaises(FrozenInstanceError):owned.enabled=False
        self.assertFalse(hasattr(owned,'ready'))
        self.assertEqual(model.select_owned([owned]),owned)

    def test_absence_and_conflicts(self):
        for raw in (b'',b'No modules.\n',b'100 other pp\n'):
            with self.assertRaises(model.ModuleError):model.select_owned(model.parse_full_listing(raw))
        for raw in (b'400 qshd pp disabled\n',b'100 qshd pp\n',b'400 qshd cil\n',
                    b'400 qshd pp\n100 qshd pp\n',b'400 qshd pp\n500 qshd pp\n',
                    b'400 qshd pp\n400 qshd pp\n'):
            with self.subTest(raw=raw),self.assertRaises(model.ModuleError):
                model.select_owned(model.parse_full_listing(raw))

    def test_malformed_and_bounded_listing(self):
        bad=(b'400 qshd pp',b'\n',b'400 qshd pp\n\n',b'No modules. \n',b'No modules.\n400 qshd pp\n',
             b'400 qshd pp\r\n',b'400 qshd\x00 pp\n',b'400 qshd pp\v\n',b'400 qshd p\xff\n',
             b'0400 qshd pp\n',b'0 qshd pp\n',b'1000 qshd pp\n',b'+400 qshd pp\n',
             b'400 -bad pp\n',b'400 qshd .pp\n',b'400 qshd pp enabled\n',
             b'400 qshd pp sha256:'+b'a'*64+b'\n',b'400 '+b'a'*129+b' pp\n',
             b'400 qshd pp'+b' '*1014+b'\n',b' '*1048577)
        for raw in bad:
            with self.subTest(length=len(raw)),self.assertRaises(model.ModuleError) as caught:model.parse_full_listing(raw)
            self.assertLess(len(str(caught.exception)),80)
        with self.assertRaises(model.ModuleError):model.parse_full_listing('400 qshd pp\n')
        rows=b''.join(f'100 module{i} pp\n'.encode() for i in range(4096))
        self.assertEqual(len(model.parse_full_listing(rows)),4096)
        with self.assertRaises(model.ModuleError):model.parse_full_listing(rows+b'100 extra pp\n')
        self.assertEqual(model.parse_full_listing(b'400\tqshd\tpp   \n')[0].name,'qshd')

    def test_direct_models_and_sequences(self):
        for args in ((True,'qshd','pp',True),(400.0,'qshd','pp',True),(400,'qshd','pp',1),
                     (400,False,'pp',True),(400,'qshd','bad value',True),(400,'qshd','pp',None)):
            with self.assertRaises(model.ModuleError):model.ModuleEntry(*args)
        good=model.ModuleEntry(400,'qshd','pp',True)
        for entries in (None,'qshd',{good},[good,object()],(x for x in [good]),[good]*4097):
            with self.assertRaises(model.ModuleError):model.select_owned(entries)
        with self.assertRaises(model.ModuleError):model.select_owned([good,good])

    def test_exact_hll_and_digest_bounds(self):
        data=b'synthetic public module bytes\x00\xff';digest=hashlib.sha256(data).hexdigest()
        identity=model.verify_hll(data,digest)
        self.assertEqual((identity.byte_length,identity.sha256),(len(data),digest))
        with self.assertRaises(FrozenInstanceError):identity.byte_length=0
        for raw,expected in ((data,'f'*64),(b'',hashlib.sha256(b'').hexdigest()),('text',digest),
                             (data,'A'*64),(data,False),(b'x'*(16*1024*1024+1),digest)):
            with self.assertRaises(model.ModuleError):model.verify_hll(raw,expected)
        for args in ((True,'a'*64),(0,'a'*64),(1,'BAD')):
            with self.assertRaises(model.ModuleError):model.HllIdentity(*args)

if __name__ == '__main__':unittest.main()
