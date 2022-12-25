#pragma once

#include <stdlib.h>
#include <givaro/modular-integer.h>
#include <Common.h>

using namespace std;
using namespace Givaro;

typedef Modular<Integer> ZP;
typedef ZP::Element Element;

bool isPrimeNumber(const Integer& n);

class Point
{
    public:
        Point();
        Point(const Point& p);
        Point(const Element& x, const Element& y);
        
        const Element& getX() const { return m_x; }
        const Element& getY() const { return m_y; }
        bool isIdentity() const { return m_isIdentity; }

        void setX(Element x) { m_x = x; }
        void setY(Element y) { m_y = y; }
        void setIdentity(bool isIdentity) { m_isIdentity = isIdentity; }

        Point operator=(const Point& P);
        bool operator==(const Point& P) const;
        void print() const;
        
    private:    
        bool m_isIdentity;
        Element m_x, m_y;
};

class EllipticCurve
{
    public:
        EllipticCurve(const EllipticCurve& c);
        EllipticCurve(const Integer& fieldOrder, const Integer& A, const Integer& B);
        EllipticCurve(const Integer& fieldOrder, const Integer& A, const Integer& B, const Point& G, const Integer& generatorOrder);

        const Integer getFieldOrder() const { return m_FField.size(); }
        const Point& getGenerator() const { return m_G; }
        const Integer& getGeneratorOrder() const { return m_GOrder; }

        Point p_scalar(const Point &P, const Integer& k) const;

        Integer generate_RFC6979_nonce(const Integer& x, const Bitstream& h, const uint8_t nonce_to_skip = 0) const;

        void print() const;
        void print_cyclic_subgroups() const;

        inline bool operator==(const EllipticCurve& c) const { return getFieldOrder() == c.getFieldOrder() && m_A == c.getA() && m_B == c.getB() && m_G == c.getGenerator() && m_GOrder == c.getGeneratorOrder(); }

    protected:
        Point p_inv(const Point& P) const;
        Point p_add(const Point &P, const Point& Q) const;
        bool verifyPoint(const Point& P) const;
        bool verifyPointOrder(const Point& P, const Integer& order = 0) const;

    protected:
        bool isZeroDiscriminant() const;
        
        Point p_double(const Point& P) const;    

        const ZP& getField() const { return m_FField; };
        const Element& getA() const { return m_A; };
        const Element& getB()const { return m_B; };

        bool isInv(const Point& Q, const Point& P) const;
        Element getY2(const Element& X) const;

        bool sqrtmod(Integer& root, const Integer& n, const bool imparity) const;

        bool recover( Point& pubkeyPoint,
              	      const Bitstream& msg_hash, const Integer& r, const Integer& s, const bool imparity,
                      const bool recover_alternate = false ) const;

    private:
        ZP m_FField;
        Element m_A, m_B;
        Point m_G;
        Integer m_GOrder;
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
        static Secp256k1 *m_sInstancePtr;
};

class Secp256r1: public EllipticCurve
{   
    public:
        static Secp256r1& GetInstance();
        Secp256r1(const Secp256r1& obj) = delete;

    private:
        //private constructor
        Secp256r1();
    
    private:
        static Secp256r1 *m_sInstancePtr;
};