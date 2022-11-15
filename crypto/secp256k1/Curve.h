#pragma once

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