#include <stdio.h>


int cnt=1;

void test(char* point)
{

    printf("%d[ point ]: %p\n",cnt++,point);

    printf("%d[ point ]: %c\n",cnt++,*point);
    *point = 'B';
    printf("%d[ point ]: %c\n",cnt++,*point);
}
void main()
{
    char* point;

    point = 'A';
    printf("%d[ point ]: %p\n",cnt++,&point);
    printf("%d[ point ]: %c\n",cnt++,point);
    test(&point);
    printf("%d[ point ]: %p\n",cnt++,&point);
    printf("%d[ point ]: %c\n",cnt++,point);
}
