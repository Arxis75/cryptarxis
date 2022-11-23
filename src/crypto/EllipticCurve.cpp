#include "EllipticCurve.h"

using namespace std;

Curve::~Curve()
{
	free(FField);
}

Curve::Curve(Integer primeField, Integer A, Integer B)
{
    FField = new ZP(primeField);
	FField->init(A,A);
	FField->init(B,B); 

    if( isZeroDiscriminant() )
    {
        cerr << "[!] Curve not defined, disriminant is Zero" << endl;
        cout << "[+ INFO ] Field : Z/" << primeField << "Z" << endl;
        cout << "[+ INFO ] A : " << A << " ; B : " << B << endl; 
        abort();
    }
}

bool Curve::isZeroDiscriminant(){
    Element Acube, Bsquare;
    FField->mul(Acube, A, A);
    FField->mulin(Acube, A);
    FField->mulin(Acube, Integer("4"));

    FField->mul(Bsquare, B, B);
    FField->mulin(Bsquare, Integer("27"));

    FField->addin(Acube, Bsquare);
    return FField->isZero(Acube);
}

Point::Point(Element x, Element y):identity(false) {
	x = x;
	y = y;
}

Point Point::operator =(const Point& P)
{
	if(P.identity)
    {
	    identity = true;
	    return *this;
    }

    identity=P.identity;
    x = P.x;
    y = P.y;
    return *this;
}

bool Point::operator ==(const Point& P) const
{
	return (identity && P.identity) || (!identity && !P.identity && x == P.x && y == P.y);
}

void Point::print() {
	identity ? cout << "infinity "<< endl :cout << "[" << x << ","
	<< y << "]" << endl;
}

EllipticCurve::EllipticCurve(Integer primeField, Integer A, Integer B)
{
	curve = new Curve(primeField, A, B);
	FField = curve->getField();
    identity.setIdentity(true);
}

EllipticCurve::~EllipticCurve()
{
    free(curve);
    free(FField);
}

const Point& EllipticCurve::_inv(Point& Q, const Point& P)
{
	if( P.isIdentity() )
		Q.setIdentity(true);
	else
	{
		Q.setIdentity(false);
		Q.setX(P.getX());
        Element tmp;
		FField->sub(tmp,FField->zero,P.getY());
        Q.setY(tmp);
		
	}
    return Q;
}

Point& EllipticCurve::_double(Point& R, const Point& P)
{
	Point tmp;
	_inv(tmp,P);

	if( P.isIdentity() || (tmp == P) )
	    R.setIdentity(true);
	else
	{
		R.setIdentity(false);
		Element tmp;
		Element xs; // 3*x^2
		FField->mul(xs,P.getX(),P.getX());
		FField->init(tmp,(uint64_t)3);
        FField->mulin(xs,tmp);

		Element ty; // 2*y
        FField->init(tmp,(uint64_t)2);
        FField->mul(ty,P.getY(),tmp);

		Element slope; // m
        FField->add(tmp,xs,curve->getA());
        FField->div(slope,tmp,ty);

		Element slope2; // m^2
        FField->mul(slope2,slope,slope);

		Element tx; // 2x
		FField->add(tx,P.getX(),P.getX());

		Element x3; // x_3
        FField->sub(x3,slope2,tx);

		Element y3; // y_3
        FField->sub(tmp,P.getX(),x3);
        FField->sub(y3,FField->mulin(tmp, slope),P.getY());

        R.setX(x3);
        R.setY(y3);
	}
    return R;
}


Point& EllipticCurve::_add(Point& R, const Point& P, const Point& Q)
{
	Point tmp1, tmp2;
	_inv(tmp1, P);
	_inv(tmp2, Q);

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
    	return _double(R,P);

    R.setIdentity(false);
	Element tmp;
	Element num; // y2 - y1
	FField->sub(num,Q.getY(),P.getY());

	Element den; // x2 - x1
	FField->sub(den,Q.getX(),P.getX());

	Element slope; // m
	FField->div(slope,num,den);

	Element slope2; // m^2
	FField->mul(slope2,slope,slope);

	Element x3; // x_3
	FField->sub(x3,slope2,FField->add(tmp,Q.getX(),P.getX()));

	Element diffx3; // x_1 - x_3
	FField->sub(diffx3,P.getX(),x3);

	Element y3; // y_3
	FField->mul(tmp,slope,diffx3);
	FField->sub(y3,tmp,P.getY());
	
    R.setX(x3);
    R.setY(y3);

    return R;
}


Point& EllipticCurve::_scalar(Point& R, const Point& P, Integer k)
{
	if(P.isIdentity())
	{
		R.setIdentity(true);
		return R;
	}

	Point tmp1, tmp2;
	R.setIdentity(true);
	Point PP = P;
	while(k > 0)
    {
		if (k % 2 == 1)
		{
			_add(tmp1,R,PP);
			R = tmp1;
		}
		tmp2 = _double(tmp2,PP);
		PP = tmp2;
		k >>= 1;
	}
	return R;
}

bool EllipticCurve::verifyPoint(const Point& P) const
{
	if(P.isIdentity())
		return true;

	Element x3,y2;
	Element Ax,rhs;
	FField->mul(x3,P.getX(),P.getX());
    FField->mulin(x3,P.getX());
	FField->mul(Ax,P.getX(),curve->getA());
    
    FField->add(rhs,x3,Ax);
    FField->addin(rhs,curve->getB());

    FField->mul(y2,P.getY(),P.getY());
    return y2==rhs;
}