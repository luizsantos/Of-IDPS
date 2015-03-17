#!/bin/bash
set -x
TMP=`mktemp -d`
CWD=`pwd`

VERSION=`grep -m 1 version pom.xml`
if [[ $VERSION =~ ^.*\<version\>([0-9.]*)\<\/version\>.*$ ]]; then
    VERSION=${BASH_REMATCH[1]}
    echo "$VERSION"
else
    echo "Failure determining version"
    exit 1
fi

mvn clean package

# Delete any existing archives
rm -rf ${CWD}/dist
mkdir -p ${CWD}/dist

cp -ar ${CWD}/target/openflowj-${VERSION}.jar ${CWD}/dist
cp -ar ${CWD}/target/openflowj-${VERSION}-sources.jar ${CWD}/dist

mkdir -p ${TMP}/openflowj-${VERSION}
cp -ar * ${TMP}/openflowj-${VERSION}
cp -ar .classpath .settings .project ${TMP}/openflowj-${VERSION}
tar -czv -f ${CWD}/dist/openflowj-${VERSION}-source.tar.gz --exclude-vcs --exclude="openflowj-${VERSION}/dist" --exclude="openflowj-${VERSION}/ext" --exclude="**/target" --exclude="**/bin" -C ${TMP} openflowj-${VERSION}

mvn javadoc:jar
cp -ar ${CWD}/target/apidocs dist/
cp -ar ${CWD}/target/openflowj-${VERSION}-javadoc.jar ${CWD}/dist

rm -rf ${TMP}

exit
