from setuptools import setup


setup(name='wincrypto',
      version='0.1',
      description='Windows Crypto API compatible decryption/encryption',
      url='http://github.com/crappycrypto/wincrypto',
      author='crappycrypto',
      author_email='crappycrypto@xs4all.nl',
      license='MIT',
      packages=['wincrypto'],
      install_requires=[
          'pycrypto',
      ],
      zip_safe=False,
      test_suite='tests')