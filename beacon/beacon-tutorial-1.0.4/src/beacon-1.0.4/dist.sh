#!/bin/bash
set -ex
TMP=`mktemp -d`
CWD=`pwd`

ARCHIVE_DIR="net.beaconcontroller.product/target/products"
ARCHIVE_NAMES=("beacon-all-linux.gtk.x86_64.tar.gz" "beacon-all-linux.gtk.x86.tar.gz" "beacon-all-macosx.cocoa.x86_64.tar.gz" "beacon-all-win32.win32.x86_64.zip" "beacon-all-win32.win32.x86.zip")
ARCHIVE_LEARNINGSWITCH="beacon-learningswitch-linux.gtk.x86.tar.gz"
NEW_ARCHIVE_DIR="dist/"
NEW_ARCHIVE_NAMES=("beacon-version-linux_x86_64.tar.gz" "beacon-version-linux_x86.tar.gz" "beacon-version-osx_x86_64.tar.gz" "beacon-version-win_x86_64.zip" "beacon-version-win_x86.zip")
ADDITIONAL_FILES=("LICENSE.txt" "beacon.properties" "README")
ECLIPSE_FILES=("eclipse-rcp-indigo-linux-gtk-x86_64.tar.gz" "eclipse-rcp-indigo-linux-gtk.tar.gz" "eclipse-rcp-indigo-macosx-cocoa-x86_64.tar.gz" "eclipse-rcp-indigo-win32-x86_64.zip" "eclipse-rcp-indigo-win32.zip")
TUTORIAL_ARCHIVE_NAMES=("beacon-tutorial-eclipse-version-linux_x86_64.tar.gz" "beacon-tutorial-eclipse-version-linux_x86.tar.gz" "beacon-tutorial-eclipse-version-osx_x86_64.tar.gz" "beacon-tutorial-eclipse-version-win_x86_64.zip" "beacon-tutorial-eclipse-version-win_x86.zip")
TUTORIAL_ARCHIVE="beacon-tutorial-version.tar.gz"
LOCAL_TARGET_ARCHIVE="beacon-local-target-version.tar.gz"
TUTORIAL=0

getExt() {
    mkdir -p ext
    cd ext
    for ECLIPSE_FILE in "${ECLIPSE_FILES[@]}"; do
        if [[ ! -e "${ECLIPSE_FILE}" ]]; then
            wget http://mirrors.xmission.com/eclipse/technology/epp/downloads/release/indigo/R/${ECLIPSE_FILE}
        fi
    done
    cd ..
}

while getopts ":t" opt; do
    case $opt in
        t ) TUTORIAL=1 ;;
        * )  ;;  
    esac
done
shift $(($OPTIND - 1)) 

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 [-t] <VERSION> <OpenFlowJ directory>"
  echo "       $0 1.0.0 ../openflowj"
  exit 65
fi

VERSION=$1
OFJ=$2
OFJ_VERSION=`grep -m 1 version ${OFJ}/pom.xml`
if [[ $OFJ_VERSION =~ ^.*\<version\>([0-9.]*)\<\/version\>.*$ ]]; then
    OFJ_VERSION=${BASH_REMATCH[1]}
    pushd .
    cd ${OFJ}
    mvn clean install
    ./dist.sh
    popd
else
    echo "Failure determining OFJ version"
    exit 1
fi

cd net.beaconcontroller.parent
mvn clean
mvn install
cd ..

# Make dist if does not exit
mkdir -p dist

# Delete any existing archives
rm -rf ${CWD}/dist/*

# Repack each archive with additional files listed above
MAXIT=`expr ${#ARCHIVE_NAMES[@]} - 1`
for i in `seq 0 ${MAXIT}`; do
    ARCHIVE_NAME=${ARCHIVE_NAMES[$i]}
    # Extract existing archive
    if [[ $ARCHIVE_NAME =~ ^.*gz$ ]]; then
        tar xzvf ${ARCHIVE_DIR}/${ARCHIVE_NAME} -C ${TMP}
    fi
    if [[ $ARCHIVE_NAME =~ ^.*zip$ ]]; then
        unzip ${ARCHIVE_DIR}/${ARCHIVE_NAME} -d ${TMP}
    fi
   
    # Add missing files
    RELEASE_DIR=`\ls ${TMP}`
    for FILE in "${ADDITIONAL_FILES[@]}"; do
        cp -a ${CWD}/${FILE} ${TMP}/${RELEASE_DIR}/
    done
    # Add learningswitch only configuration
    # runnable via ./beacon -configuration ./configurationSwitch
    mv ${TMP}/${RELEASE_DIR}/configuration ${TMP}/${RELEASE_DIR}/configurationT
    tar xzvf ${CWD}/${ARCHIVE_DIR}/${ARCHIVE_LEARNINGSWITCH} -C ${TMP} ${RELEASE_DIR}/configuration
    mv ${TMP}/${RELEASE_DIR}/configuration ${TMP}/${RELEASE_DIR}/configurationSwitch
    mv ${TMP}/${RELEASE_DIR}/configurationT ${TMP}/${RELEASE_DIR}/configuration
    
    # Repack archive
    if [[ $ARCHIVE_NAME =~ ^.*gz$ ]]; then
        tar czvf ${NEW_ARCHIVE_DIR}/${NEW_ARCHIVE_NAMES[$i]//version/$VERSION} -C ${TMP} ${RELEASE_DIR}
    fi
    if [[ $ARCHIVE_NAME =~ ^.*zip$ ]]; then
        pushd .
        cd ${TMP}
        zip -r ${CWD}/${NEW_ARCHIVE_DIR}/${NEW_ARCHIVE_NAMES[$i]//version/$VERSION} *
        popd
    fi
        
    rm -rf ${TMP}/*
done
mkdir -p ${TMP}/beacon-${VERSION}
cp -ar * ${TMP}/beacon-${VERSION}
tar -czv -f ${CWD}/dist/beacon-${VERSION}-source.tar.gz --exclude-vcs --exclude="beacon-${VERSION}/dist" --exclude="beacon-${VERSION}/ext" --exclude="**/target" --exclude="**/bin" --exclude="**/logs" -C ${TMP} beacon-${VERSION}
rm -rf ${TMP}/*

cd net.beaconcontroller.parent
mvn javadoc:javadoc
cd ..
rm -rf dist/javadoc dist/apidocs
cp -ar net.beaconcontroller.parent/target/site/apidocs dist/

if [[ $TUTORIAL -eq 1 ]]; then
    echo "=== BUILDING TUTORIAL ==="
    getExt
    # Assemble the tutorial packages
    mkdir ${TMP}/beacon-tutorial-${VERSION}
    cp -ar ${CWD}/dist/apidocs ${TMP}/beacon-tutorial-${VERSION}
    mkdir ${TMP}/beacon-tutorial-${VERSION}/src
    tar xvzf ${CWD}/dist/beacon-${VERSION}-source.tar.gz -C ${TMP}/beacon-tutorial-${VERSION}/src
    tar xvzf ${OFJ}/dist/openflowj-${OFJ_VERSION}-source.tar.gz -C ${TMP}/beacon-tutorial-${VERSION}/src
    # extract the local target files here
    tar xzvf ${CWD}/ext/${LOCAL_TARGET_ARCHIVE//version/$VERSION} -C ${TMP}/beacon-tutorial-${VERSION}/src/beacon-${VERSION}
    # build the package without eclipse
    tar czvf ${CWD}/dist/${TUTORIAL_ARCHIVE//version/$VERSION} -C ${TMP} beacon-tutorial-${VERSION}
    # per eclipse version
    
    # Repack each archive with additional files listed above
    MAXIT=`expr ${#ECLIPSE_FILES[@]} - 1`
    for i in `seq 0 ${MAXIT}`; do
        ECLIPSE_FILE=${ECLIPSE_FILES[$i]}
        TUT_ARCHIVE=${TUTORIAL_ARCHIVE_NAMES[$i]}
        rm -rf ${TMP}/beacon-tutorial-${VERSION}/eclipse
    
        # Extract the eclipse archive
        if [[ $ECLIPSE_FILE =~ ^.*gz$ ]]; then
            tar xzvf ${CWD}/ext/${ECLIPSE_FILE} -C ${TMP}/beacon-tutorial-${VERSION}
        fi
        if [[ $ECLIPSE_FILE =~ ^.*zip$ ]]; then
            unzip ${CWD}/ext/${ECLIPSE_FILE} -d ${TMP}/beacon-tutorial-${VERSION}
        fi
        
        # Pack archive
        if [[ $TUT_ARCHIVE =~ ^.*gz$ ]]; then
            tar czvf ${CWD}/dist/${TUT_ARCHIVE//version/$VERSION} -C ${TMP} beacon-tutorial-${VERSION}
        fi
        if [[ $TUT_ARCHIVE =~ ^.*zip$ ]]; then
            pushd .
            cd ${TMP}
            zip -r ${CWD}/dist/${TUT_ARCHIVE//version/$VERSION} *
            popd
        fi
    done
fi

rm -rf ${TMP}
echo "=== BUILD COMPLETE - FILES PLACED IN ${CWD}/dist ==="

