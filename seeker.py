import textwrap
import argparse

from core.shodanseeker import ShodanSeeker
import config


class NullOutput(object):
    def write(self, text):
        pass

    def flush(self):
        pass


if __name__ == "__main__":
    ShodanSeeker(config).run()
