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
    # parser = argparse.ArgumentParser()
    # args = vars(parser.parse_args())
    app = ShodanSeeker(config)
    app.run()
