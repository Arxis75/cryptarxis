#pragma once

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