"""
Script to compare the components, functions, classes, and permissions in
two BOM files.
"""

import json
import logging
import os.path
import sys


def compare(bom_file1, bom_file2):
    """
    Compares two Bill of Materials (BOM) files and prints the common components,
    functions, classes, and permissions.

    Args:
        bom_file1: The path to the first BOM file.
        bom_file2: The path to the second BOM file.

    """
    bom1_data, bom2_data = get_boms(bom_file1, bom_file2)

    comps_1, funcs_1, classes_1 = process_components(bom1_data['components'])
    comps_2, funcs_2, classes_2 = process_components(bom2_data['components'])

    permissions_1 = get_permissions(bom1_data['metadata']['component'])
    permissions_2 = get_permissions(bom2_data['metadata']['component'])

    common_components = comps_1.intersection(comps_2)
    common_permissions = permissions_1.intersection(permissions_2)
    common_functions = funcs_1.intersection(funcs_2)
    common_classes = classes_1.intersection(classes_2)

    print(f'common components: {len(common_components)}')
    print(f'common functions: {len(common_functions)}')
    print(f'common classes: {len(common_classes)}')
    print(f'common permissions: {len(common_permissions)}')


def get_boms(bom_file1, bom_file2):
    """Loads and returns the contents of two Bill of Materials (BOM) files.

    Args:
        bom_file1: The path to the first BOM file.
        bom_file2: The path to the second BOM file.

    Returns:
        Two dictionaries representing the contents of the BOM files.

    """
    if not os.path.isfile(bom_file1) or not os.path.isfile(bom_file2):
        logging.error('Error: One or both BOM files do not exist.')
        sys.exit(1)

    with open(bom_file1, 'r', encoding='utf-8') as f:
        bom1_data = json.load(f)

    with open(bom_file2, 'r', encoding='utf-8') as f:
        bom2_data = json.load(f)

    return bom1_data, bom2_data


def get_permissions(bom):
    """Extracts the permissions from the Bill of Materials (BOM).

    Args:
        bom: A dictionary representing the Bill of Materials (BOM).

    Returns:
        A set containing the extracted permissions.

    """
    bom_permissions = []
    for i in bom.get('properties'):
        if 'permissions' in i.get('name', '').lower():
            permission_list = i['value'].split('\n')
            bom_permissions.extend(p.split(' ')[0] for p in permission_list)

    return set(bom_permissions)


def process_components(components):
    """
    Processes the components to extract the names, functions, and classes.

    Args:
        components: A list of dictionaries representing the components.

    Returns:
        A tuple containing three sets: names, functions, and classes.

    """
    bom_components = []
    bom_functions = []
    bom_classes = []
    for i in components:
        bom_components.append(i.get('name'))
        for prop in i.get('properties', []):
            if 'functions' in prop.get('name', '').lower():
                bom_functions.extend(prop.get('value', '').split(', '))
            elif 'classes' in prop.get('name', '').lower():
                bom_classes.extend(prop.get('value', '').split(', '))

    return set(bom_components), set(bom_functions), set(bom_classes)


if __name__ == "__main__":
    compare(sys.argv[1], sys.argv[2])
