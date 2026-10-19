# SPDX-License-Identifier: MPL-2.0
"""RFC 6238 Appendix B vectors and independent PyOTP cross-checks."""
import base64, hashlib, time, unittest
import pyotp
from totp_auth import generate, classify

class TotpTests(unittest.TestCase):
    def test_rfc6238_all_algorithms_and_64bit_time(self):
        vectors=[(59,'94287082','46119246','90693936'),(1111111109,'07081804','68084774','25091201'),(1111111111,'14050471','67062674','99943326'),(1234567890,'89005924','91819424','93441116'),(2000000000,'69279037','90698825','38618901'),(20000000000,'65353130','77737706','47863826')]
        for at,*expected in vectors:
            for size,algorithm,answer in zip([20,32,64],['sha1','sha256','sha512'],expected):
                secret=base64.b32encode(('1234567890'*7)[:size].encode()).decode()
                self.assertEqual(generate(secret,at//30,8,algorithm),answer)
    def test_pyotp_independent_current_wrong_expired_and_window(self):
        for _ in range(20):
            secret=pyotp.random_base32();authenticator=pyotp.TOTP(secret)
            now=int(time.time());counter=now//30
            for delta in [-1,0,1]:
                code=authenticator.at((counter+delta)*30)
                self.assertEqual(classify(secret,code,now)[0],counter+delta)
            expired=authenticator.at((counter-3)*30)
            self.assertEqual(classify(secret,expired,now),(None,'expired'))
            wrong=next(str(i).zfill(6) for i in range(100) if classify(secret,str(i).zfill(6),now)[1]=='invalid')
            self.assertEqual(classify(secret,wrong,now),(None,'invalid'))
            self.assertEqual(generate(secret,counter),authenticator.at(now))
    def test_format_rejection(self):
        secret=pyotp.random_base32()
        for code in ['', '12345','1234567','１２３４５６','abc123','123456\n']:
            self.assertEqual(classify(secret,code)[1],'invalid')
if __name__=='__main__':unittest.main()
