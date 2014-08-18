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
      test_suite='tests',
      classifiers=[
          "Development Status :: 3 - Alpha",
          "Topic :: Security :: Cryptography",
          "License :: OSI Approved :: MIT License",
      ])