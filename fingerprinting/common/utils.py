# -*- coding: utf-8 -*-

import os
import yaml


def delete_output_directory(output_directory):

    for filename in os.listdir(output_directory):

        relative_path = os.path.join(output_directory, filename)

        if os.path.isfile(relative_path):
            os.unlink(relative_path)


def get_output_directory(pcap_filename):

    absolute_path = os.path.dirname(pcap_filename)
    output_directory, _ = os.path.splitext(os.path.basename(pcap_filename))

    return os.path.join(absolute_path, output_directory)


def create_output_directory(output_directory):

    if os.path.exists(output_directory):
        delete_output_directory(output_directory)
    else:
        os.mkdir(output_directory)


def walk_directory(pcap_directory_or_file, handler):

    base_directory = os.getcwd()

    for root, _, files in os.walk(pcap_directory_or_file):

        current = os.path.join(base_directory, root)

        for filename in files:

            if not validate_extension(os.path.join(current, filename), "pcap"):
                continue

            handler(os.path.join(current, filename))


def read_pickle(filename, classname):

    with open(filename, mode="rb") as fp:

        contents = yaml.load(fp)

        if isinstance(contents, classname):
            return contents
        else:
            raise Exception("[E] Serialized object not an instance of <Application>")


def write_pickle(filename, contents):

    print("\n[<] Writing output %s..." % os.path.basename(filename))

    with open(filename, "w") as fp:
        yaml.dump(contents, fp, default_flow_style=None)


def write_yaml(filename, contents):

    print("\n[<] Writing output %s..." % os.path.basename(filename))

    with open(filename, "w") as fp:
        yaml.dump(contents, fp, default_flow_style=None)


def replace_extension(filename, extension):

    return os.path.splitext(filename)[0] + "." + extension


def validate_extension(filename, extension):

    return os.path.isfile(filename) and os.path.splitext(filename)[-1].lower()[1:] == extension
