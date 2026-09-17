

import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from labs.lab01.task1 import run_task1
from labs.lab01.task2 import run_task2
from labs.lab01.task3 import run_task3


def main() -> None:
    run_task1()
    run_task2()
    run_task3()


if __name__ == "__main__":
    main()