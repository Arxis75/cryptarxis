#include "EllipticCurve.h"

Point::Point(bool b) {
	this->identity = b;
}


Point::Point(Element x, Element y):identity(false) {
	this->x = x;
	this->y = y;
}


Point Point::operator =(const Point& P) {
	if(P.identity)
	    {
	    this->identity = true;
	    return *this;
	    }

	    this->identity=P.identity;
	    this->x = P.x;
	    this->y = P.y;
	    return *this;
}


bool Point::operator ==(const Point& P) const {
	return (this->identity && P.identity) ||
	                        (!this->identity && !P.identity && this->x == P.x && this->y == P.y);
}


void Point::print() {
	this->identity ? std::cout << "infinity "<< std::endl :std::cout << "[" << this->x << ","
	<< this->y << "]" << std::endl;
}

Curve::Curve() {
	Integer p;
	do {
        std::cout<< "Enter the Prime modulo p :";
        std::cin>>p;
        this->FField = new ZP(p);
        std::cout << "Enter A : ";
        this->FField->read(std::cin,this->A);
        std::cout << "Enter B : ";
        this->FField->read(std::cin,this->B);
        std::cout<< std::endl;
        }
    while (this->isZeroDiscriminant());
	}


Curve::~Curve() {
	free(FField);
}

Curve::Curve(Integer primeField, Integer A, Integer B)
    {
    this->FField = new ZP(primeField);
	this->FField->init(this->A,A);
	this->FField->init(this->B,B); 

    if (this->isZeroDiscriminant()){
        std::cerr << "[!] Curve not defined, disriminant is Zero" << std::endl;
        std::cout << "[+ INFO ] Field : Z/" << primeField << "Z" << std::endl;
        std::cout << "[+ INFO ] A : " << A << " ; B : " << B << std::endl; 
        abort();
        }
    }
void Curve::print() {
    std::cout << " Field : Z/" << this->FField->residu() << "Z" << std::endl;
    std::cout << " A :" ;
    this->FField->write(std::cout,this->A);
    std::cout << ", B :";
    this->FField->write(std::cout,this->B);
    std::cout<< std::endl;
}

bool Curve::isZeroDiscriminant(){
    Element Acube, Bsquare;
    this->FField->mul(Acube, this->A, this->A);
    this->FField->mulin(Acube, this->A);
    this->FField->mulin(Acube, Integer("4"));

    this->FField->mul(Bsquare, this->B, this->B);
    this->FField->mulin(Bsquare, Integer("27"));

    this->FField->addin(Acube, Bsquare);
    return this->FField->isZero(Acube);
}

EllipticCurve::EllipticCurve(Integer primeField, Integer A, Integer B)
    {
	this->curve = new Curve(primeField, A, B);
	this->FField = this->curve->getField();
    this->identity.setIdentity(true);
    }


EllipticCurve::EllipticCurve(Curve* curve) {
    this->curve = curve;
    this->FField = this->curve->getField();
    this->identity.setIdentity(true);
	}

EllipticCurve::~EllipticCurve() {
    free(curve);
    free(FField);
	}


const Point& EllipticCurve::_inv(Point& Q, const Point& P) {
	if(P.isIdentity())
	{
		Q.setIdentity(true);
		return Q;
	}
	else
	{
		Q.setIdentity(false);
		Q.setX(P.getX());
        Element tmp;
		this->FField->sub(tmp,this->FField->zero,P.getY());
        Q.setY(tmp);
		return Q;
	}
	}



Point& EllipticCurve::_double(Point& R, const Point& P) {
	Point tmp;
	this->_inv(tmp,P);
	if(P.isIdentity() || (tmp == P))
	    {
	    R.setIdentity(true);
	    return R;
	    }
	else
		{
		//
		R.setIdentity(false);
		Element tmp;
		Element xs; // 3*x^2
		this->FField->mul(xs,P.getX(),P.getX());
		this->FField->init(tmp,(uint64_t)3);
        this->FField->mulin(xs,tmp);
        //
		Element ty; // 2*y
        this->FField->init(tmp,(uint64_t)2);
        this->FField->mul(ty,P.getY(),tmp);
		//
		Element slope; // m
        this->FField->add(tmp,xs,this->curve->getA());
        this->FField->div(slope,tmp,ty);
		//
		Element slope2; // m^2
        this->FField->mul(slope2,slope,slope);
		//
		Element tx; // 2x
		this->FField->add(tx,P.getX(),P.getX());
        //
		Element x3; // x_3
        this->FField->sub(x3,slope2,tx);
		//
		Element y3; // y_3
        this->FField->sub(tmp,P.getX(),x3);
        this->FField->sub(y3,this->FField->mulin(tmp, slope),P.getY());

        R.setX(x3);
        R.setY(y3);
        return R;
		}
	}


Point& EllipticCurve::_add(Point& R, const Point& P, const Point& Q) {
	Point tmp1, tmp2;
	this->_inv(tmp1, P);
	this->_inv(tmp2, Q);
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
		return this->_double(R,P);
	   }
	//
    R.setIdentity(false);
	Element tmp;
	Element num; // y2 - y1
	this->FField->sub(num,Q.getY(),P.getY());
	//
	Element den; // x2 - x1
	this->FField->sub(den,Q.getX(),P.getX());
	//
	Element slope; // m
	this->FField->div(slope,num,den);
	//
	Element slope2; // m^2
	this->FField->mul(slope2,slope,slope);
	// 
	Element x3; // x_3
	this->FField->sub(x3,slope2,this->FField->add(tmp,Q.getX(),P.getX()));
	//
	Element diffx3; // x_1 - x_3
	this->FField->sub(diffx3,P.getX(),x3);
	//
	Element y3; // y_3
	this->FField->mul(tmp,slope,diffx3);
	this->FField->sub(y3,tmp,P.getY());
	
    R.setX(x3);
    R.setY(y3);
    return R;
	}


Point& EllipticCurve::_scalar(Point& R, const Point& P, Integer k) {
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
			this->_add(tmp1,R,PP);
			R = tmp1;
			}
		tmp2 = this->_double(tmp2,PP);
		PP = tmp2;
		k >>= 1;
		}
	return R;
	}


bool EllipticCurve::verifyPoint(const Point& P) const {
	if(P.isIdentity())
	{
		return true;
	}
	Element x3,y2;
	Element Ax,rhs;
	this->FField->mul(x3,P.getX(),P.getX());
    this->FField->mulin(x3,P.getX());
	this->FField->mul(Ax,P.getX(),this->curve->getA());
    
    this->FField->add(rhs,x3,Ax);
    this->FField->addin(rhs,this->curve->getB());

   
    this->FField->mul(y2,P.getY(),P.getY());
    return y2==rhs;
}


void EllipticCurve::print() {
	std::cout<<"Elliptic Curve Defined by ";
	std::cout<<"y^2 = x^3 + ";
	this->FField->write(std::cout,this->curve->getA());
	std::cout<<"x + ";
	this->FField->write(std::cout,this->curve->getB());
	std::cout<<std::endl;
	//std::cout << this->FField->Modular_implem() << std::endl;
}

Secp256k1* Secp256k1::instancePtr = NULL;

Secp256k1::Secp256k1(Integer primeField, Integer A, Integer B)
    : EllipticCurve(primeField, A, B)
    , p(primeField)
    , G(Integer("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
        Integer("32670510020758816978083085130507043184471273380659243275938904335757337482424"))
    , n(Integer("115792089237316195423570985008687907852837564279074904382605163141518161494337"))
{
}

Secp256k1& Secp256k1::GetInstance()
{
    if (instancePtr == NULL)
    {
        Integer p("115792089237316195423570985008687907853269984665640564039457584007908834671663");
        Integer A("0");
        Integer B("7");
        instancePtr = new Secp256k1(p, A, B);
    }

    return *instancePtr;
}

Point Secp256k1::Gmul(Integer& k)
{
    Point R;
    assert(k > 0 && k < getCurveOrder());
    _scalar(R,G,k);
    assert(verifyPoint(R));
    return R;
}