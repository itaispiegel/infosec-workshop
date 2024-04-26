all: project.tab lex.yy.c a.out

project.tab: project.y
	bison -d project.y

lex.yy.c: project.l
	lex project.l

a.out: lex.yy.c project.tab.c project.tab.h
	gcc -o a.out project.tab.c lex.yy.c -lfl -lm

clean:
	rm -f a.out lex.yy.c y.output project.tab.c project.tab.h
