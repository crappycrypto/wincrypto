from setuptools import setup

setup(name='wincrypto',
      version='0.3',
      description='Windows Crypto API compatible decryption/encryption',
      url='http://github.com/crappycrypto/wincrypto',
      author='crappycrypto',
      author_email='crappycrypto@xs4all.nl',
      license='MIT',
      packages=['wincrypto'],
      install_requires=[
          'pycryptodome',
      ],
      test_suite='tests',
      classifiers=[
          "Development Status :: 3 - Alpha",
          "Topic :: Security :: Cryptography",
          "License :: OSI Approved :: MIT License",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7",
          "Programming Language :: Python :: 3.8",
      ])
