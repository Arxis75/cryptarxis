#pragma once

#include <stdlib.h>
#include <givaro/modular-integer.h>

using namespace Givaro;

typedef Modular<Integer> ZP;
typedef ZP::Element Element;

class Curve
{
    public:
        Curve(Integer primeField, Integer A, Integer B);
        ~Curve();
                
        ZP* getField() {return FField;};
        Element getA() {return A;};
        Element getB() {return B;};
        
        bool isZeroDiscriminant();

    private:
        ZP* FField;
        Element A,B;
};

class Point
{
    public:
        Point() : identity(true) {}
        Point(Element x, Element y);

        Element getX() const {return x;};
        Element getY() const {return y;};
        void setX(Element _x) {x = _x;};
        void setY(Element _y) {y = _y;};
        void setIdentity(bool _identity) {identity = _identity;};

        bool isIdentity() const {return identity;};

        Point operator=(const Point& P);
        bool operator==(const Point& P) const;

        void print();
    
    private:
        bool identity;
        Element x,y;
};

class EllipticCurve
{
    public:
        EllipticCurve(Integer primeField, Integer A, Integer B);
        ~EllipticCurve();

        const Point& _inv(Point& Q, const Point& P);
        bool _isInv(const Point& Q, const Point& P);
        Point& _double(Point& R, const Point& P);
        Point& _add(Point&R, const Point &P, const Point& Q);
        Point& _scalar(Point& R, const Point& P,Integer k);

        bool verifyPoint(const Point& P) const;

    private:
        Curve *curve;
        ZP *FField;
        Point identity;
};