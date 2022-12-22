#include <gtest/gtest.h>
#include <crypto/bips.h>

using namespace std;
using namespace BIP39;

TEST(SignatureTests, RFC6979_NIST_P256)
{
    EllipticCurve ecc = Secp256r1::GetInstance();
    Privkey x(Integer(Bitstream("0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 256, 16)), ecc);
    const char* message = "sample";
    Bitstream t_raw(message,strlen(message)<<3);
    Bitstream t_h(t_raw.sha256());

    Pubkey U = x.getPubKey();
    Integer expected = Bitstream("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 256, 16);
    Integer actual = U.getPoint().getX();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 256, 16);
    actual = U.getPoint().getY();
    ASSERT_EQ(actual, expected);

    expected = Bitstream("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60", 256, 16);
    actual = ecc.generate_RFC6979_nonce(x.getSecret(), t_h, 0);
    ASSERT_EQ(actual, expected);

    Signature expected_signature( Bitstream("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", 256, 16),
                                  Bitstream("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8", 256, 16),
                                  false );
    Signature actual_signature = x.sign(t_h, false);    //malleability not enforced by default in the RFC
    expected = expected_signature.get_imparity();
    actual = actual_signature.get_imparity();
    ASSERT_EQ(actual, expected);
    expected = expected_signature.get_r();
    actual = actual_signature.get_r();
    ASSERT_EQ(actual, expected);
    expected = expected_signature.get_s();
    actual = actual_signature.get_s();
    ASSERT_EQ(actual, expected);
}

TEST(SignatureTests, Micah_sign_vectors)
{
    const char* message = "hello";
    Bitstream t_raw(message,strlen(message)<<3);
    Bitstream t_h(t_raw.keccak256());

    Privkey x(Integer(Bitstream("1", 256, 16)));
    Signature expected_signature( Bitstream("433EC3D37E4F1253DF15E2DEA412FED8E915737730F74B3DFB1353268F932EF5", 256, 16),
                                  Bitstream("557C9158E0B34BCE39DE28D11797B42E9B1ACB2749230885FE075AEDC3E491A4", 256, 16),
                                  false );
    Signature actual_signature = x.sign(t_h);
    Integer expected = expected_signature.get_imparity();
    Integer actual = actual_signature.get_imparity();
    ASSERT_EQ(actual, expected);
    expected = expected_signature.get_r();
    actual = actual_signature.get_r();
    ASSERT_EQ(actual, expected);
    expected = expected_signature.get_s();
    actual = actual_signature.get_s();
    ASSERT_EQ(actual, expected);

    x = Privkey(Integer(Bitstream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 256, 16)));
    expected_signature = Signature( Bitstream("45CEA25D72DB4929DC27BC66527BBB215D20E323FF0DE944640930BE5C38C534", 256, 16),
                                    Bitstream("34F8904BDE08FB97BE5D01C6BC5AF0189FD76E0E03693E56DAB28BFCD956F150", 256, 16),
                                    true );
    actual_signature = x.sign(t_h);
    expected = expected_signature.get_imparity();
    actual = actual_signature.get_imparity();
    ASSERT_EQ(actual, expected);
    expected = expected_signature.get_r();
    actual = actual_signature.get_r();
    ASSERT_EQ(actual, expected);
    expected = expected_signature.get_s();
    actual = actual_signature.get_s();
    ASSERT_EQ(actual, expected);
}

TEST(SignatureTests, Micah_verify_vectors)
{
    const char* message = "hello";
    Bitstream t_raw(message,strlen(message)<<3);
    Bitstream t_h(t_raw.keccak256());

    Privkey x(Integer(Bitstream("1", 256, 16)));
    Signature sig( Bitstream("433EC3D37E4F1253DF15E2DEA412FED8E915737730F74B3DFB1353268F932EF5", 256, 16),
                   Bitstream("557C9158E0B34BCE39DE28D11797B42E9B1ACB2749230885FE075AEDC3E491A4", 256, 16),
                   false );
                                  
    bool expected = true;
    bool actual = sig.isValid(t_h, x.getPubKey().getAddress());
    ASSERT_EQ(actual, expected);

    x = Privkey(Integer(Bitstream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 256, 16)));
    sig = Signature( Bitstream("45CEA25D72DB4929DC27BC66527BBB215D20E323FF0DE944640930BE5C38C534", 256, 16),
                     Bitstream("34F8904BDE08FB97BE5D01C6BC5AF0189FD76E0E03693E56DAB28BFCD956F150", 256, 16),
                     true );
    expected = true;
    actual = sig.isValid(t_h, x.getPubKey().getAddress());
    ASSERT_EQ(actual, expected);

    x = Privkey(Integer(Bitstream("1", 256, 16)));
    sig = Signature( Bitstream("1", 256, 16),
                     Bitstream("1", 256, 16),
                     true );
    expected = false;
    actual = sig.isValid(t_h, x.getPubKey().getAddress());
    ASSERT_EQ(actual, expected);

    x = Privkey(Integer(Bitstream("1", 256, 16)));
    sig = Signature( Bitstream("1", 256, 16),
                     Bitstream("1", 256, 16),
                     false );
    expected = false;
    actual = sig.isValid(t_h, x.getPubKey().getAddress());
    ASSERT_EQ(actual, expected);
}

TEST(SignatureTests, Micah_recover_vectors)
{
    Pubkey k;
    const char* message = "hello";
    Bitstream t_raw(message,strlen(message)<<3);
    Bitstream t_h(t_raw.keccak256());

    Privkey x(Integer(Bitstream("1", 256, 16)));
    Signature sig = x.sign(t_h);
    sig.ecrecover(k, t_h);                                  
    Point expected = x.getPubKey().getPoint();
    Point actual = k.getPoint();
    ASSERT_EQ(actual, expected);

    x = Privkey(Integer(Bitstream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 256, 16)));
    sig = x.sign(t_h);
    sig.ecrecover(k, t_h);  
    expected = x.getPubKey().getPoint();
    actual = k.getPoint();
    ASSERT_EQ(actual, expected);

    x = Privkey(Integer(Bitstream("1", 256, 16)));
    sig = Signature( Bitstream("1", 256, 16),
                     Bitstream("1", 256, 16),
                     false );
    bool bexpected = false;
    bool bactual = sig.ecrecover(k, t_h);
    ASSERT_EQ(bactual, bexpected);
}