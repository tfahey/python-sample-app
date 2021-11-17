from setuptools import setup

# Used in pypi.org as the README description of your package
with open("README.md", 'r') as f:
    long_description = f.read()

# Remove this whole block from here...
setup(
        name='python-sample-app',
        version='1.0',
        description='python-sample-app is a starter template for new python applications',
        author='Thomas Fahey',
        author_email='tntfahey@gmail.com',
        license="MIT",
        url="https://github.com/tfahey/python-sample-app",
        packages=['python_sample_app'],
        entry_points={
                'console_scripts': [
                    'sample-app=python_sample_app.main:main',
                ],
        },
        long_description=long_description
)
exit(0)
# ...to here. Then edit the following block to match your project needs

setup(
        name='<your_project>',
        version='<your_project_version>',
        description='<your_project_description>',
        author='<your_name>',
        author_email='<you@example.com>',
        license="<your_project_license>",
        url="<your_project_url>",
        packages=['<your_project_main_package>'],
        #scripts=['scripts/some_script.py'],
        #python_requires='>=3',
        entry_points={
                'console_scripts': [
                    '<your_command>=<your_project_main_package>.main:main',
                ],
        },
        #install_requires=['foo', 'bar'], # Install External packages 'foo' and 'bar' as dependencies
        long_description=long_description
)
