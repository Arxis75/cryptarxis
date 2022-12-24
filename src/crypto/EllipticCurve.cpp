
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
	: identity(p.isIdentity())
	, x(p.getX())
	, y(p.getY())
{}
        bool identity;
        Element x,y;

Point::Point()
	: identity(true)
	, x(0)
	, y(0)
{}

Point::Point(const Element& _x, const Element& _y)
	:identity(false)
	, x(_x)
	, y(_y)
{}

Point Point::operator=(const Point& P)
{
	if(P.identity)
		identity = true;
	else
	{
		identity = false;
		x = P.x;
		y = P.y;
	}
	return *this;
}

bool Point::operator==(const Point& P) const
{
	return (identity && P.identity) || (!identity && !P.identity && x == P.x && y == P.y);
}


void Point::print() const
{
	(identity ? cout << "infinity " : cout << "(" << x << "," << y << ")") << endl;
}

EllipticCurve::EllipticCurve(const EllipticCurve& curve)
	: _FField(ZP(curve._FField))
	, _A(curve._A)
	, _B(curve._B)
    , _G(curve._G)
    , _genOrder(curve._genOrder)
{ }

EllipticCurve::EllipticCurve(const Integer& fieldOrder, const Integer& A, const Integer& B)
	: _FField(ZP(fieldOrder))
	, _A(A)
	, _B(B)
    , _G(Point())
    , _genOrder(0)
{
	assert( !isZeroDiscriminant() );
	//assert( isPrimeNumber(_FField.size()) );
	assert( _FField.size()%4 == 3 );			//for fast sqrt
}

EllipticCurve::EllipticCurve(const Integer& fieldOrder, const Integer& A, const Integer& B, const Point& G, const Integer& generatorOrder)
	: _FField(ZP(fieldOrder))
	, _A(A)
	, _B(B)
    , _G(G)
    , _genOrder(generatorOrder)
{
	assert( !isZeroDiscriminant() );
	//assert( isPrimeNumber(_FField.size()) );
	assert( _FField.size()%4 == 3 );			//for fast sqrt
	assert( verifyPoint(G) );
	//assert( isPrimeNumber(_genOrder) );	//TODO: calculate pointOrder instead of passing it as a parameter
}

bool EllipticCurve::isZeroDiscriminant() const
{
    Element Acube, Bsquare;
    _FField.mul(Acube, _A, _A);
    _FField.mulin(Acube, _A);
    _FField.mulin(Acube, Integer("4"));

    _FField.mul(Bsquare, _B, _B);
    _FField.mulin(Bsquare, Integer("27"));

    _FField.addin(Acube, Bsquare);
    return _FField.isZero(Acube);
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
		_FField.sub(tmp, _FField.zero, P.getY());
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
		_FField.mul(xs, P.getX(), P.getX());
		_FField.init(tmp, (uint64_t)3);
        _FField.mulin(xs, tmp);
        
		Element ty; // 2*y
        _FField.init(tmp, (uint64_t)2);
        _FField.mul(ty, P.getY(), tmp);
		
		Element slope; // m
        _FField.add(tmp, xs, getA());
        _FField.div(slope, tmp, ty);
		
		Element slope2; // m^2
        _FField.mul(slope2, slope, slope);
		
		Element tx; // 2x
		_FField.add(tx, P.getX(), P.getX());
        
		Element x3; // x_3
        _FField.sub(x3, slope2, tx);
		
		Element y3; // y_3
        _FField.sub(tmp, P.getX(), x3);
        _FField.sub(y3, _FField.mulin(tmp, slope), P.getY());

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
		_FField.sub(num, Q.getY(), P.getY());

		Element den; // x2 - x1
		_FField.sub(den, Q.getX(), P.getX());

		Element slope; // m
		_FField.div(slope, num,den);

		Element slope2; // m^2
		_FField.mul(slope2, slope, slope);

		Element tmp, x3; // x_3
		_FField.sub(x3, slope2, _FField.add(tmp, Q.getX(), P.getX()));

		Element diffx3; // x_1 - x_3
		_FField.sub(diffx3, P.getX(), x3);

		Element y3; // y_3
		_FField.mul(tmp, slope, diffx3);
		_FField.sub(y3, tmp, P.getY());
		
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
	_FField.init(X, _X);

	Element x3, Ax, rhs;
	_FField.mul(x3, X, X);
	_FField.mulin(x3, X);

	_FField.mul(Ax, X, getA());
	
	_FField.add(rhs, x3, Ax);
	_FField.addin(rhs, getB());

	return rhs;
}

bool EllipticCurve::verifyPoint(const Point& P) const
{
	bool ret = true;
	if( !P.isIdentity() )
	{
		Element y2;
		_FField.mul(y2, P.getY(), P.getY());

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
	_FField.write(cout, getA());
	cout<<"x + ";
	_FField.write(cout, getB());
	cout<<endl;
	//cout << _FField.Modular_implem() << endl;
}

void EllipticCurve::print_cyclic_subgroups() const
{
	for(Integer x=0;x<_FField.size();x++)
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
						cout << "G(" << dec << x << "," << y << ")" << " solution of y²=x³+7 [" << _FField.size() << "]" << endl;
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

Integer EllipticCurve::generate_RFC6979_nonce(const Bitstream& x, const Bitstream& h, const uint8_t nonce_to_skip) const
{
	assert(_genOrder > 0);
	assert(Integer(x) > 0 && Integer(x) < getGeneratorOrder()  && h.bitsize() == 256);

	unsigned char *res;
	uint32_t dilen;
	Bitstream V("0x0101010101010101010101010101010101010101010101010101010101010101", 256, 16);
	Bitstream K("0x0000000000000000000000000000000000000000000000000000000000000000", 256, 16);
	Bitstream V_;

	V_ = Bitstream(V);
	V_.push_back(0x00,8);
	V_.push_back(x,256);
	V_.push_back(h, h.bitsize());
	// K = HMAC(K, V || 0x00 || int2octets(x) || bits2octets(h))
	res = HMAC( EVP_sha256(), K, 32, V_, V_.bitsize()>>3, K, &dilen );
	// V = HMAC(K, V)
	res = HMAC( EVP_sha256(), K, 32, V, V.bitsize()>>3, V, &dilen );

	V_ = Bitstream(V);
	V_.push_back(0x01,8);
	V_.push_back(x,256);
	V_.push_back(h, h.bitsize());
	// K = HMAC(K, V || 0x01 || int2octets(x) || bits2octets(h))
	res = HMAC( EVP_sha256(), K, 32, V_, V_.bitsize()>>3, K, &dilen );
	// V = HMAC(K, V)
	res = HMAC( EVP_sha256(), K, 32, V, V.bitsize()>>3, V, &dilen );

	Bitstream k;
	uint8_t counter = 0;
	while(true)
	{
		// V = HMAC(K, V)
		res = HMAC( EVP_sha256(), K, 32, V, V.bitsize()>>3, V, &dilen );
		//k ||= V
		k = V;
		if( counter >= nonce_to_skip && Integer(k) > 0 && Integer(k) < getGeneratorOrder() )
			break;
		
		V_ = Bitstream(V);
		V_.push_back(0x00,8);
		// K = HMAC(K, V || 0x00)
		res = HMAC( EVP_sha256(), K, 32, V_, V_.bitsize()>>3, K, &dilen );
		// V = HMAC(K, V)
		res = HMAC( EVP_sha256(), K, 32, V, V.bitsize()>>3, V, &dilen );
		counter++;
	}

	return k;    
}

bool EllipticCurve::sqrtmod(Integer& root, const Integer& value, const bool imparity) const
{
	Integer y;
    y = powmod(value, (_FField.size()+1)>>2, _FField.size());
    if( isOdd(y) != imparity )
        y = _FField.size() - y;
    bool ret = (powmod(y, 2, _FField.size()) == value);
    if(ret)
        root = y;
    return ret;
}

bool EllipticCurve::recover( Point& Q_candidate,
                			 const Bitstream& msg_hash, const Integer& r, const Integer& s, const bool imparity,
							 const bool recover_alternate ) const
{
	assert(_genOrder > 0);
    assert(msg_hash.bitsize() == 256);
    assert(r < _genOrder);
    assert(s < _genOrder);

    bool ret = false;

    Integer r_candidate = r + (recover_alternate ? _genOrder : Integer(0));
    if( r_candidate < _FField.size() )
    {
		Integer y_candidate;
		if( sqrtmod(y_candidate, getY2(r_candidate), imparity) )
		{
			Point R = Point(r_candidate, y_candidate);
			if( verifyPoint(R) && verifyPointOrder(R) )
			{
				cout << hex << "R_candidate = (0x" << R.getX() << ", 0x" << R.getY() << ")" << endl;
				Point sR = p_scalar(R, s);
				//cout << hex << "sR = (0x" << sR.getX() << ", 0x" << sR.getY() << ")" << endl;
				Point hG =  p_scalar(_G, msg_hash);
				//cout << hex << "hG = (0x" << hG.getX() << ", 0x" << hG.getY() << ")" << endl;
				Point invhG = p_inv(hG);
				//cout << hex << "_hG = (0x" << invhG.getX() << ", 0x" << invhG.getY() << ")" << endl;
				Point sR_hG = p_add(sR, invhG);
				//cout << hex << "sR_hG = (0x" << sR_hG.getX() << ", 0x" << sR_hG.getY() << ")" << endl;
				Integer r_1;
				inv(r_1, r_candidate, _genOrder);
				//cout << hex << "r^(-1) = 0x" << r_1 << endl;
				Q_candidate = p_scalar(sR_hG, r_1);
				if( verifyPoint(Q_candidate) && verifyPointOrder(Q_candidate) )
				{
					cout << hex << "Q_candidate = (0x" << Q_candidate.getX() << ", 0x" << Q_candidate.getY() << ")" << endl;
					ret = true;
				}
			}
			else
				cout << "invalid signature!" << endl;
		}
    }
    return ret;
}

Secp256k1* Secp256k1::instancePtr = NULL;

Secp256k1::Secp256k1()
    : EllipticCurve( Integer("115792089237316195423570985008687907853269984665640564039457584007908834671663"),
					 0, 7,
					 Point(Integer("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
        				   Integer("32670510020758816978083085130507043184471273380659243275938904335757337482424")),
    				 Integer("115792089237316195423570985008687907852837564279074904382605163141518161494337") )
{}

Secp256k1& Secp256k1::GetInstance()
{
    if (instancePtr == NULL)
        instancePtr = new Secp256k1();

    return *instancePtr;
}

Secp256r1* Secp256r1::instancePtr = NULL;

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
    if (instancePtr == NULL)
        instancePtr = new Secp256r1();

    return *instancePtr;
}