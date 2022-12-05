#include "EllipticCurve.h"
#include "bips.h"

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

EllipticCurve::EllipticCurve(const Integer& p, const Integer& A, const Integer& B)
	: _FField(ZP(p))
    , _p(p)
	, _A(A)
	, _B(B)
    , _G(Point())
    , _n(0)
{
	assert( !isZeroDiscriminant() );
	assert( isPrimeNumber(_p) );
	assert( _p%4 == 3 );			//for fast sqrt
}

EllipticCurve::EllipticCurve(const Integer& p, const Integer& A, const Integer& B, const Point& G, const Integer& n)
	: _FField(ZP(p))
    , _p(p)
	, _A(A)
	, _B(B)
    , _G(G)
    , _n(n)
{
	assert( !isZeroDiscriminant() );
	assert( isPrimeNumber(_p) );
	assert( _p%4 == 3 );			//for fast sqrt
	assert( verifyPoint(G) );
	assert( isPrimeNumber(_n) );	//TODO: calculate pointOrder instead of passing it as a parameter
}

bool EllipticCurve::sqrtmod(Integer& root, const Integer& n, const bool parity) const
{
	Integer r;
    r = powmod(n, (_p+1)>>2, _p);
    if( parity == isOdd(r) )
        r = _p - r;
    bool ret = (powmod(r, 2, _p) == n);
    if(ret)
        root = r;
    return ret;
}

bool EllipticCurve::ecrecover(Point& pubkeyPoint,
                			  const bitstream& msg_hash, const Integer& r, const Integer& s, const bool parity,
                			  const bitstream& from_address ) const
{

    assert(msg_hash.bitsize() == 256);
    assert(r < _n);
    assert(s < _n);
    assert(from_address.bitsize() == 160);

    bool ret = false;
	Point Q_candidate;
    Integer r_candidate = r;
    while(!ret && r_candidate < _p)
    {
        Integer y_candidate;
        if( sqrtmod(y_candidate, getY2(r_candidate), parity) )
        {
            Point R = Point(r_candidate, y_candidate);
			cout << dec << "R_candidate = (" << R.getX() << "," << R.getY() << ")" << endl;
            Point sR = p_scalar(R, s);
			cout << dec << "sR = (" << sR.getX() << "," << sR.getY() << ")" << endl;
            Point hG =  p_scalar(_G, msg_hash);
			cout << dec << "hG = (" << hG.getX() << "," << hG.getY() << ")" << endl;
            Point _hG = p_inv(hG);
			cout << dec << "_hG = (" << _hG.getX() << "," << _hG.getY() << ")" << endl;
            Point sR_hG = p_add(sR, _hG);
			cout << dec << "sR_hG = (" << sR_hG.getX() << "," << sR_hG.getY() << ")" << endl;
            Integer r_1;
			inv(r_1, r_candidate, _n);
			cout << dec << "r^(-1) = " << r_1 << endl;
            Q_candidate = p_scalar(sR_hG, r_1);
        	cout << dec << "Q_candidate = (" << Q_candidate.getX() << "," << Q_candidate.getY() << ")" << endl;
			BIP32::pubkey pubkey_candidate(Q_candidate);
        	cout << dec << "Address(Q_candidate) = 0x" << pubkey_candidate.getAddress() << endl;
            ret = (pubkey_candidate.getAddress() == from_address);
        }
        r_candidate += _n;
    }
	if(ret)
		pubkeyPoint = Q_candidate;
    return ret;
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
	Point tmp1, tmp2;
	tmp1 = p_inv(P);
	tmp2 = p_inv(Q);
	if((P.isIdentity() && Q.isIdentity()) || (tmp1 == Q) || (tmp2 == P))
		{
	    R.setIdentity(true);
	    return R;
	    }
	if (P.isIdentity())
	    {
	    R = Q;
	    return R;
	    }
	if (Q.isIdentity())
	    {
	    R = P;
	    return R;
	    }
	if(P==Q)
	   {
		return p_double(P);
	   }
	//
    R.setIdentity(false);
	Element tmp;
	Element num; // y2 - y1
	_FField.sub(num,Q.getY(),P.getY());
	//
	Element den; // x2 - x1
	_FField.sub(den,Q.getX(),P.getX());
	//
	Element slope; // m
	_FField.div(slope,num,den);
	//
	Element slope2; // m^2
	_FField.mul(slope2,slope,slope);
	// 
	Element x3; // x_3
	_FField.sub(x3,slope2,_FField.add(tmp,Q.getX(),P.getX()));
	//
	Element diffx3; // x_1 - x_3
	_FField.sub(diffx3,P.getX(),x3);
	//
	Element y3; // y_3
	_FField.mul(tmp,slope,diffx3);
	_FField.sub(y3,tmp,P.getY());
	
    R.setX(x3);
    R.setY(y3);
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