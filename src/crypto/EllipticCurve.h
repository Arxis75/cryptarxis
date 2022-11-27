#pragma once

#include <stdlib.h>
#include <givaro/modular-integer.h>

using namespace Givaro;

typedef Modular<Integer> ZP;
typedef ZP::Element Element;

class Point
{
private:
    
    bool identity;
    Element x,y;
public:

    Point() : identity(true) {}
    Point(bool b);
    Point(Element x, Element y);
    Element getX() const{
        return this->x;
    };
    void setX(Element _x){
        this->x = _x;
    }
    Element getY() const{
        return this->y;
    };

    void setY(Element _y) {
        this->y = _y;
    };

    bool isIdentity() const{
        return this->identity;
    };

    void setIdentity(bool _identity){
        this->identity = _identity;
    };

    Point operator=(const Point& P);
    bool operator==(const Point& P) const;
    void print();
};

class Curve
    {
    private:
        ZP* FField;
        Element A,B;

    public:
        Curve();
        Curve(Integer primeField, Integer A, Integer B);
        ~Curve();
        bool isZeroDiscriminant();
        ZP *getField()
            {
            return this->FField;
            };

        Element getA(){
            return this->A;
        };
        Element getB(){
            return this->B;
        };
        void print(); 
    };

    class EllipticCurve
{
private:
    typedef ZP::Element Element;
    Curve *curve;
    ZP *FField;
    Point identity;
public:
    EllipticCurve(Curve *c);
    EllipticCurve(Integer primeField, Integer A, Integer B);
    ~EllipticCurve();

    const Point& _inv(Point& Q, const Point& P);
    bool _isInv(const Point& Q, const Point& P);
    Point& _double(Point& R, const Point& P);
    Point& _add(Point&R, const Point &P, const Point& Q);
    Point& _scalar(Point& R, const Point& P,Integer k);

    bool verifyPoint(const Point& P) const;
    void print();

};

class Secp256k1: public EllipticCurve
{   
    public:
        static Secp256k1& GetInstance();
        Secp256k1(const Secp256k1& obj) = delete;
        Point Gmul(Integer& k);
        const Integer getFieldOrder() const { return p; }
        const Integer getCurveOrder() const { return n; }

    private:
        Secp256k1(Integer primeField, Integer A, Integer B);
    
    private:
        const Integer p;
        const Point G;
        const Integer n;
        static Secp256k1* instancePtr;
};