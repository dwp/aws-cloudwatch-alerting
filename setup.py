"""setuptools packaging."""

import setuptools

setuptools.setup(
    name="aws_cloudwatch_alerting",
    version="0.0.1",
    author="DWP DataWorks",
    author_email="dataworks@digital.uc.dwp.gov.uk",
    description="A lambda that processed alerts from cloudwatch in to slack",
    long_description="A lambda that processed alerts from cloudwatch in to slack",
    long_description_content_type="text/markdown",
    entry_points={
        "console_scripts": [
            "aws_cloudwatch_alerting=aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting:main"
        ]
    },
    package_dir={"": "src"},
    packages=setuptools.find_packages("src"),
    install_requires=["argparse", "boto3"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
