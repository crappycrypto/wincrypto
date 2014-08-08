import unittest

import wincrypto


class TestJoke(unittest.TestCase):
    def test_is_string(self):
        s = wincrypto.test()
        self.assertTrue(isinstance(s, basestring))


if __name__ == '__main__':
    unittest.main()