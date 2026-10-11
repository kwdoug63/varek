/* Two threads of one process each launch an allowed program at once. */
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
static pthread_barrier_t b;
static void *t1(void *x) { (void)x; pthread_barrier_wait(&b); execl("/usr/bin/echo", "echo", "A", (char *)0); return 0; }
static void *t2(void *x) { (void)x; pthread_barrier_wait(&b); execl("/usr/bin/true", "true", (char *)0); return 0; }
int main(void) {
    int killed = 0, ok = 0, other = 0;
    for (int i = 0; i < 100; i++) {
        pid_t p = fork();
        if (p == 0) {
            pthread_t a, c;
            pthread_barrier_init(&b, 0, 2);
            pthread_create(&a, 0, t1, 0); pthread_create(&c, 0, t2, 0);
            pthread_join(a, 0); _exit(9);
        }
        int st; waitpid(p, &st, 0);
        if (WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL) killed++;
        else if (WIFEXITED(st) && WEXITSTATUS(st) == 0) ok++;
        else other++;
    }
    printf("RESULT ok %d killed %d other %d\n", ok, killed, other);
    return 0;
}
