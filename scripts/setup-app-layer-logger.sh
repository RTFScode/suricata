#! /usr/bin/env bash

set -e

# Fail if "ed" is not available.
if ! which ed > /dev/null 2>&1; then
    echo "error: the program \"ed\" is required for this script"
    exit 1
fi

function usage() {
    cat <<EOF

usage: $0 <protocol name>

This script will provision a new JSON application layer transaction
logger for the protocol name specified on the command line. This is
done by copying and patching src/output-json-template.h and
src/output-json-template.c then link the new files into the build
system.

It is required that the application layer parser has already been
provisioned by the setup-app-layer.sh script.

Examples:

    $0 DNP3
    $0 Gopher

EOF
}

# Make sure we are running from the correct directory.
set_dir() {
    if [ -e ./suricata.c ]; then
	cd ..
    elif [ -e ./src/suricata.c ]; then
	# Do nothing.
	true
    else
	echo "error: this does not appear to be a suricata source directory."
	exit 1
    fi
}

fail_if_exists() {
    path="$1"
    if test -e "${path}"; then
	echo "error: ${path} already exists."
	exit 1
    fi
}

function copy_template_file() {
    src="$1"
    dst="$2"

    echo "Creating ${dst}."
    
    sed -e '/TEMPLATE_START_REMOVE/,/TEMPLATE_END_REMOVE/d' \
	-e "s/TEMPLATE/${protoname_upper}/g" \
	-e "s/template/${protoname_lower}/g" \
	-e "s/Template/${protoname}/g" \
	> ${dst} < ${src}
}

function copy_templates() {
    src_h="src/output-json-template.h"
    dst_h="src/output-json-${protoname_lower}.h"
    src_c="src/output-json-template.c"
    dst_c="src/output-json-${protoname_lower}.c"

    fail_if_exists ${dst_h}
    fail_if_exists ${dst_c}

    copy_template_file ${src_h} ${dst_h}
    copy_template_file ${src_c} ${dst_c}
}

function patch_makefile_am() {
    filename="src/Makefile.am"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/output-json-template.c
t-
s/template/${protoname_lower}/g
w
EOF
}

patch_suricata_common_h() {
    filename="src/suricata-common.h"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/LOGGER_JSON_TEMPLATE
t-
s/TEMPLATE/${protoname_upper}
w
EOF
}

function patch_output_c() {
    filename="src/output.c"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
# Find #include output-json-template.h and duplicate it for new protocol.
/#include "output-json-template.h"
t-
s/template/${protoname_lower}/
# Find JsonTemplateLogRegister() then backup one line to its comment.
/JsonTemplateLogRegister
-
# Copy the current line and the next line up a line.
.,+t-
# Go back a line so we're at the first copied line.
-
# Now rename to the new protocol name.
.,+s/Template/${protoname}/
# Write.
w
EOF
}

patch_suricata_yaml_in() {
    filename="suricata.yaml.in"
    echo "Patching ${filename}."
    ed -s ${filename} > /dev/null <<EOF
/eve-log:
/types:
a
        - ${protoname_lower}
.
w
EOF
}

set_dir

protoname="$1"

# Make sure the protocol name looks like a proper name (starts with a
# capital letter).
case "${protoname}" in

    [[:upper:]]*)
	# OK.
	;;

    "")
	usage
	exit 1
	;;

    *)
	echo "error: protocol name must beging with an upper case letter"
	exit 1
	;;

esac

protoname_lower=$(printf ${protoname} | tr '[:upper:]' '[:lower:]')
protoname_upper=$(printf ${protoname} | tr '[:lower:]' '[:upper:]')

# Requires that the protocol has already been setup.
if ! grep -q "ALPROTO_${protoname_upper}" src/app-layer-protos.h; then
    echo "error: no app-layer parser exists for ALPROTO_${protoname_upper}."
    exit 1
fi

copy_templates
patch_makefile_am
patch_suricata_common_h
patch_output_c
patch_suricata_yaml_in

cat <<EOF

A JSON application layer transaction logger for the protocol
${protoname} has now been set in the files:

    src/output-json-${protoname_lower}.h
    src/output-json-${protoname_lower}.c

and should now build cleanly. Try running 'make'.

EOF
