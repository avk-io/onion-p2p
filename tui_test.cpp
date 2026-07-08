#include <ncurses.h>

int main(){
    initscr();
    cbreak();
    noecho();
    curs_set(1);

    printw("Hello from ncurses! press any key to exit");
    refresh();

    getch();

    endwin();
    return 0;
}