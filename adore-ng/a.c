
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#define ELITE_UID 2618748389U
#define ELITE_GID 4063569279U

int main(){
if(lchown("./aa.txt", ELITE_UID, ELITE_GID)>=0)printf("OK\n");

return 0;

}
