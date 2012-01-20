TRUNK=../openbts-p2.8
COM=$(TRUNK)/CommonLibs
#SR=$(TRUNK)/subscriberRegistry/trunk-public-staging
LOCALLIBS=$(COM)/Logger.cpp $(COM)/Timeval.cpp $(COM)/Threads.cpp $(COM)/Sockets.cpp $(COM)/Configuration.cpp $(SQL)/sqlite3util.cpp SubscriberRegistry.cpp servershare.cpp
LIBS=$(LOCALLIBS) -losipparser2 -losip2 -lc -lpthread -lsqlite3 `pkg-config --libs libosmogsm` `pkg-config --libs libosmocore`
INCLUDES=-I$(COM) -I$(SQL)
CPPFLAGS=-g -Wall -pipe

all: srmanager.cgi subscriberserver.cgi sipauthserve

srmanager.cgi: srmanager.cpp $(LOCALLIBS)
	g++ -o srmanager.cgi $(CPPFLAGS) $(INCLUDES) srmanager.cpp $(LIBS)

subscriberserver.cgi: subscriberserver.cpp $(LOCALLIBS)
	g++ -o subscriberserver.cgi $(CPPFLAGS) $(INCLUDES) subscriberserver.cpp $(LIBS)

sipauthserve: sipauthserve.cpp $(LOCALLIBS)
	g++ -o sipauthserve $(CPPFLAGS) $(INCLUDES) sipauthserve.cpp $(LIBS)

clean:
	rm -f srmanager.cgi subscriberserver.cgi sipauthserve test.SubscriberRegistry/test
	rm -r -f *.dSYM
