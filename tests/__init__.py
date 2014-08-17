import platform

from tests.algorithms import *

if platform.system() == 'Windows':
    from tests.native import *

if __name__ == '__main__':
    unittest.main()