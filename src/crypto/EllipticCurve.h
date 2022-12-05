#pragma once

#include <stdlib.h>
#include <givaro/modular-integer.h>
#include <Common.h>

using namespace Givaro;

typedef Modular<Integer> ZP;
typedef ZP::Element Element;

bool isPrimeNumber(const Integer& n);

class Point
{
    public:
        Point();
        Point(const Element& _x, const Element& _y);
        
        const Element& getX() const { return x; }
        const Element& getY() const { return y; }
        bool isIdentity() const { return identity; }

        void setX(Element _x) { x = _x; }
        void setY(Element _y) { y = _y; }
        void setIdentity(bool _identity) { identity = _identity; }

        Point operator=(const Point& P);
        bool operator==(const Point& P) const;
        void print() const;
        
    private:    
        bool identity;
        Element x,y;
};

class EllipticCurve
{
    public:
        EllipticCurve(const Integer& p, const Integer& A, const Integer& B);
        EllipticCurve(const Integer& p, const Integer& A, const Integer& B, const Point& G, const Integer& n);

        const Integer& getFieldOrder() const { return _p; }
        const Point& getGenerator() const { return _G; }
        const Integer& getCurveOrder() const { return _n; }

        Point p_inv(const Point& P) const;
        Point p_add(const Point &P, const Point& Q) const;
        Point p_double(const Point& P) const;
        Point p_scalar(const Point &P, const Integer& k) const;

        bool ecrecover(Point& pubkeyPoint,
                	   const bitstream& msg_hash, const Integer& r, const Integer& s, const bool parity,
                	   const bitstream& from_address ) const;

        bool verifyPoint(const Point& P) const;
        void print() const;

        Element getY2(const Element& X) const;
        bool sqrtmod(Integer& root, const Integer& n, const bool parity) const;

    protected:
        const ZP& getField() const { return _FField; };
        const Element& getA() const { return _A; };
        const Element& getB()const { return _B; };

        bool isInv(const Point& Q, const Point& P) const;
        bool isZeroDiscriminant() const;

    private:
        const ZP _FField;
        const Integer _p;
        const Element _A, _B;
        const Point _G;
        const Integer _n;
};

class Secp256k1: public EllipticCurve
{   
    public:
        static Secp256k1& GetInstance();
        Secp256k1(const Secp256k1& obj) = delete;

    private:
        //private constructor
        Secp256k1();
    
    private:
        static Secp256k1* instancePtr;
};