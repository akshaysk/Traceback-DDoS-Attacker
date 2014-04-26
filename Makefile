all: traffana endhost router

traffana: traffana.o log.o
	gcc -o traffana -g -Wall traffana.o log.o -lpcap

traffana.o: traffana.c traffana.h
	gcc -g -c -Wall traffana.c -lpcap

endhost: endhost.o log.o
	gcc -o endhost -g -Wall endhost.o log.o -lpcap -lpthread

endhost.o: endhost.c endhost.h
	gcc -g -c -Wall endhost.c -lpcap

router: router.o log.o
	gcc -o router -g -Wall router.o log.o -lpcap -lpthread

router.o: router.c router.h
	gcc -g -c -Wall router.c -lpcap

log.o: log.c log.h
	gcc -g -c -Wall log.c
clean:
	rm -f *.o traffana endhost router
