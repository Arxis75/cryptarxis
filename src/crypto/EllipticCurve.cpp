
#include "EllipticCurve.h"
#include "bips.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <map>

using namespace std;

// Function that checks whether n is prime or not
bool isPrimeNumber(const Integer& n)
{
   bool isPrime = true;

   for(Integer i = 2; i <= n/2; i++) {
      if (n%i == 0) {
         isPrime = false;
         break;
      }
   }  
   return isPrime;
}

Point::Point(const Point& p)
	: m_isIdentity(p.isIdentity())
	, m_x(p.getX())
	, m_y(p.getY())
{}

Point::Point()
	: m_isIdentity(true)
	, m_x(0)
	, m_y(0)
{}

Point::Point(const Element& x, const Element& y)
	:m_isIdentity(false)
	, m_x(x)
	, m_y(y)
{}

Point Point::operator=(const Point& P)
{
	if(P.m_isIdentity)
		m_isIdentity = true;
	else
	{
		m_isIdentity = false;
		m_x = P.m_x;
		m_y = P.m_y;
	}
	return *this;
}

bool Point::operator==(const Point& P) const
{
	return (m_isIdentity && P.m_isIdentity) || (!m_isIdentity && !P.m_isIdentity && m_x == P.m_x && m_y == P.m_y);
}


void Point::print() const
{
	(m_isIdentity ? cout << "infinity " : cout << "(" << m_x << "," << m_y << ")") << endl;
}

EllipticCurve::EllipticCurve(const EllipticCurve& curve)
	: m_FField(ZP(curve.m_FField))
	, m_A(curve.m_A)
	, m_B(curve.m_B)
    , m_G(curve.m_G)
    , m_GOrder(curve.m_GOrder)
{ }

EllipticCurve::EllipticCurve(const Integer& fieldOrder, const Integer& A, const Integer& B)
	: m_FField(ZP(fieldOrder))
	, m_A(A)
	, m_B(B)
    , m_G(Point())
    , m_GOrder(0)
{
	assert( !isZeroDiscriminant() );
	//assert( isPrimeNumber(m_FField.size()) );
	assert( m_FField.size()%4 == 3 );			//for fast sqrt
}

EllipticCurve::EllipticCurve(const Integer& fieldOrder, const Integer& A, const Integer& B, const Point& G, const Integer& generatorOrder)
	: m_FField(ZP(fieldOrder))
	, m_A(A)
	, m_B(B)
    , m_G(G)
    , m_GOrder(generatorOrder)
{
	assert( !isZeroDiscriminant() );
	//assert( isPrimeNumber(m_FField.size()) );
	assert( m_FField.size()%4 == 3 );			//for fast sqrt
	assert( verifyPoint(G) );
	//assert( isPrimeNumber(m_GOrder) );	//TODO: calculate pointOrder instead of passing it as a parameter
}

bool EllipticCurve::isZeroDiscriminant() const
{
    Element Acube, Bsquare;
    m_FField.mul(Acube, m_A, m_A);
    m_FField.mulin(Acube, m_A);
    m_FField.mulin(Acube, Integer("4"));

    m_FField.mul(Bsquare, m_B, m_B);
    m_FField.mulin(Bsquare, Integer("27"));

    m_FField.addin(Acube, Bsquare);
    return m_FField.isZero(Acube);
}

Point EllipticCurve::p_inv(const Point& P) const
{
	Point Q;
	if(P.isIdentity())
		Q.setIdentity(true);
	else
	{
		Q.setIdentity(false);
		Q.setX(P.getX());
        Element tmp;
		m_FField.sub(tmp, m_FField.zero, P.getY());
        Q.setY(tmp);
	}
	return Q;
}

Point EllipticCurve::p_double(const Point& P) const
{
	Point R = p_inv(P);
	if( P.isIdentity() || R == P )
	    R.setIdentity(true);
	else
	{
		R.setIdentity(false);
		Element tmp;
		Element xs; // 3*x^2
		m_FField.mul(xs, P.getX(), P.getX());
		m_FField.init(tmp, (uint64_t)3);
        m_FField.mulin(xs, tmp);
        
		Element ty; // 2*y
        m_FField.init(tmp, (uint64_t)2);
        m_FField.mul(ty, P.getY(), tmp);
		
		Element slope; // m
        m_FField.add(tmp, xs, getA());
        m_FField.div(slope, tmp, ty);
		
		Element slope2; // m^2
        m_FField.mul(slope2, slope, slope);
		
		Element tx; // 2x
		m_FField.add(tx, P.getX(), P.getX());
        
		Element x3; // x_3
        m_FField.sub(x3, slope2, tx);
		
		Element y3; // y_3
        m_FField.sub(tmp, P.getX(), x3);
        m_FField.sub(y3, m_FField.mulin(tmp, slope), P.getY());

        R.setX(x3);
        R.setY(y3);
	}
	return R;
}


Point EllipticCurve::p_add(const Point& P, const Point& Q) const
{
	Point R;
	if( (P.isIdentity() && Q.isIdentity()) || Q == p_inv(P) || P == p_inv(Q) )
		R.setIdentity(true);
	else if (P.isIdentity())
	    R = Q;
	else if (Q.isIdentity())
	    R = P;
	else if(P==Q)
		R = p_double(P);
	else
	{
		R.setIdentity(false);
		Element num; // y2 - y1
		m_FField.sub(num, Q.getY(), P.getY());

		Element den; // x2 - x1
		m_FField.sub(den, Q.getX(), P.getX());

		Element slope; // m
		m_FField.div(slope, num,den);

		Element slope2; // m^2
		m_FField.mul(slope2, slope, slope);

		Element tmp, x3; // x_3
		m_FField.sub(x3, slope2, m_FField.add(tmp, Q.getX(), P.getX()));

		Element diffx3; // x_1 - x_3
		m_FField.sub(diffx3, P.getX(), x3);

		Element y3; // y_3
		m_FField.mul(tmp, slope, diffx3);
		m_FField.sub(y3, tmp, P.getY());
		
		R.setX(x3);
		R.setY(y3);
	}
    return R;
}

Point EllipticCurve::p_scalar(const Point& P, const Integer& k) const
{
	Point R;
	R.setIdentity(true);
	if( !P.isIdentity() )
	{
		Point PP = P;
		Integer n(k);
		while( n > 0 )
		{
			if( n % 2 == 1 )
				R = p_add(R, PP);
			PP = p_double(PP);
			n >>= 1;
		}
	}
	return R;
}

Element EllipticCurve::getY2(const Element& _X) const
{
	Element X;
	m_FField.init(X, _X);

	Element x3, Ax, rhs;
	m_FField.mul(x3, X, X);
	m_FField.mulin(x3, X);

	m_FField.mul(Ax, X, getA());
	
	m_FField.add(rhs, x3, Ax);
	m_FField.addin(rhs, getB());

	return rhs;
}

bool EllipticCurve::verifyPoint(const Point& P) const
{
	bool ret = true;
	if( !P.isIdentity() )
	{
		Element y2;
		m_FField.mul(y2, P.getY(), P.getY());

		ret = ( y2 == getY2(P.getX()) );
	}
    return ret;
}

bool EllipticCurve::verifyPointOrder(const Point& P, const Integer& order) const
{
	Point O = p_scalar(P, (order ? order : getGeneratorOrder()));
    return O.isIdentity();
}

void EllipticCurve::print() const
{
	cout<<"Elliptic Curve Defined by ";
	cout<<"y^2 = x^3 + ";
	m_FField.write(cout, getA());
	cout<<"x + ";
	m_FField.write(cout, getB());
	cout<<endl;
	//cout << m_FField.Modular_implem() << endl;
}

void EllipticCurve::print_cyclic_subgroups() const
{
	for(Integer x=0;x<m_FField.size();x++)
	{
		Element y;
		if( sqrtmod(y, getY2(x), true) )
		{  
			Point G(x,y);
			Integer k = 0;
			Point R = G;
			bool new_point = false;
			while( !R.isIdentity() )
			{
				k++;
				R = p_scalar(G,k);				
				if( !R.isIdentity())
				{
					if(!new_point)
					{
						cout << "G(" << dec << x << "," << y << ")" << " solution of y²=x³+7 [" << m_FField.size() << "]" << endl;
						new_point = true;
					}
					cout << "(" << dec << R.getX() << "," << R.getY() << ") ";
				}
				else
				{
					if( new_point )
						cout << "Point at Infinity";
				}
			}
			if( new_point )
			{
				cout << endl;
				if( k > 2 && isPrimeNumber(k) )
					cout << "Curve Order is Prime! n = " << dec << k;
				cout << endl << endl;
			}
		}
	}
}

Integer EllipticCurve::generate_RFC6979_nonce(const Integer& x, const ByteStream& h, const uint8_t nonce_to_skip) const
{
	assert(m_GOrder > 0);
	assert(x > 0 && x < getGeneratorOrder()  && h.byteSize() == 32);

	unsigned char *res;
	uint32_t dilen;
	ByteStream V("0x0101010101010101010101010101010101010101010101010101010101010101", 32, 16);
	ByteStream K("0x0000000000000000000000000000000000000000000000000000000000000000", 32, 16);
	ByteStream V_;

	V_ = ByteStream(V);
	V_.push_back(Integer::zero, 1);
	V_.push_back(x, 32);
	V_.push_back(h);
	// K = HMAC(K, V || 0x00 || int2octets(x) || bits2octets(h))
	res = HMAC( EVP_sha256(), K, 32, V_, V_.byteSize(), K, &dilen );
	// V = HMAC(K, V)
	res = HMAC( EVP_sha256(), K, 32, V, V.byteSize(), V, &dilen );

	V_ = ByteStream(V);
	V_.push_back(0x01, 1);
	V_.push_back(x, 32);
	V_.push_back(h);
	// K = HMAC(K, V || 0x01 || int2octets(x) || bits2octets(h))
	res = HMAC( EVP_sha256(), K, 32, V_, V_.byteSize(), K, &dilen );
	// V = HMAC(K, V)
	res = HMAC( EVP_sha256(), K, 32, V, V.byteSize(), V, &dilen );

	Integer k;
	uint8_t counter = 0;
	while(true)
	{
		// V = HMAC(K, V)
		res = HMAC( EVP_sha256(), K, 32, V, V.byteSize(), V, &dilen );
		//k ||= V
		k = V;
		k &= Givaro::pow(2, getGeneratorOrder().size_in_base(2)) - 1;		//truncate for testing purposes only (small fields)
		//cout << dec << "k_candidate: " << k << endl;
		if( counter >= nonce_to_skip && k > 0 && k < getGeneratorOrder() )
			break;
		
		V_ = ByteStream(V);
		V_.push_back(Integer::zero, 1);
		// K = HMAC(K, V || 0x00)
		res = HMAC( EVP_sha256(), K, 32, V_, V_.byteSize(), K, &dilen );
		// V = HMAC(K, V)
		res = HMAC( EVP_sha256(), K, 32, V, V.byteSize(), V, &dilen );
		counter++;
	}

	return k;    
}

bool EllipticCurve::sqrtmod(Integer& root, const Integer& value, const bool imparity) const
{
	Integer y;
    y = powmod(value, (m_FField.size()+1)>>2, m_FField.size());
    if( isOdd(y) != imparity )
        y = m_FField.size() - y;
    bool ret = (powmod(y, 2, m_FField.size()) == value);
    if(ret)
        root = y;
    return ret;
}

bool EllipticCurve::recover( Point& Q_candidate,
                			 const ByteStream& msg_hash, const Integer& r, const Integer& s, const bool imparity,
							 const bool recover_alternate ) const
{
	assert(m_GOrder > 0);
    assert(msg_hash.byteSize() == 32);
    assert(r < m_GOrder);
    assert(s < m_GOrder);

    bool ret = false;

    Integer r_candidate = r + (recover_alternate ? m_GOrder : Integer::zero);
    if( r_candidate < m_FField.size() )
    {
		Integer y_candidate;
		if( sqrtmod(y_candidate, getY2(r_candidate), imparity) )
		{
			Point R = Point(r_candidate, y_candidate);
			if( verifyPoint(R) && verifyPointOrder(R) )
			{
				//cout << hex << "R_candidate = (0x" << R.getX() << ", 0x" << R.getY() << ")" << endl;
				Point sR = p_scalar(R, s);
				//cout << hex << "sR = (0x" << sR.getX() << ", 0x" << sR.getY() << ")" << endl;
				Point hG =  p_scalar(m_G, msg_hash);
				//cout << hex << "hG = (0x" << hG.getX() << ", 0x" << hG.getY() << ")" << endl;
				Point invhG = p_inv(hG);
				//cout << hex << "_hG = (0x" << invhG.getX() << ", 0x" << invhG.getY() << ")" << endl;
				Point sR_hG = p_add(sR, invhG);
				//cout << hex << "sR_hG = (0x" << sR_hG.getX() << ", 0x" << sR_hG.getY() << ")" << endl;
				Integer r_1;
				inv(r_1, r_candidate, m_GOrder);
				//cout << hex << "r^(-1) = 0x" << r_1 << endl;
				Q_candidate = p_scalar(sR_hG, r_1);
				if( verifyPoint(Q_candidate) && verifyPointOrder(Q_candidate) )
				{
					//cout << hex << "Q_candidate = (0x" << Q_candidate.getX() << ", 0x" << Q_candidate.getY() << ")" << endl;
					ret = true;
				}
			}
			else
				cout << "invalid signature!" << endl;
		}
    }
    return ret;
}

Secp256k1 *Secp256k1::m_sInstancePtr = NULL;

Secp256k1::Secp256k1()
    : EllipticCurve( Integer("115792089237316195423570985008687907853269984665640564039457584007908834671663"),
					 0, 7,
					 Point(Integer("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
        				   Integer("32670510020758816978083085130507043184471273380659243275938904335757337482424")),
    				 Integer("115792089237316195423570985008687907852837564279074904382605163141518161494337") )
{}

Secp256k1& Secp256k1::GetInstance()
{
    if (m_sInstancePtr == NULL)
        m_sInstancePtr = new Secp256k1();

    return *m_sInstancePtr;
}

Secp256r1 *Secp256r1::m_sInstancePtr = NULL;

Secp256r1::Secp256r1()
    : EllipticCurve( Integer("115792089210356248762697446949407573530086143415290314195533631308867097853951"),
					 Integer("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
					 Integer("41058363725152142129326129780047268409114441015993725554835256314039467401291"),
					 Point(Integer("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
        				   Integer("36134250956749795798585127919587881956611106672985015071877198253568414405109")),
    				 Integer("115792089210356248762697446949407573529996955224135760342422259061068512044369") )
{}

Secp256r1& Secp256r1::GetInstance()
{
    if (m_sInstancePtr == NULL)
        m_sInstancePtr = new Secp256r1();

    return *m_sInstancePtr;
}