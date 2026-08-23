"""NPT v7 worker entrypoint.

The production worker is intentionally a safe queue consumer boundary. Tool execution
must be delegated through the existing control-plane checks and never accepts arbitrary
shell commands.
"""

import time


def main() -> None:
    # Queue backend integration is selected by deployment configuration. Keeping the
    # process alive here makes the container health-compatible without enabling an
    # unrestricted command runner.
    while True:
        time.sleep(30)


if __name__ == "__main__":
    main()
