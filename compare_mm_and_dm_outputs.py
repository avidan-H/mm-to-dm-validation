#!/usr/bin/python3
'''Compare the output indicators from Demisto and Minemeld respectively.

This comparison is for the outputs of both products when they are configured with the following feeds:
* DShield Blocklist
* SpamHaus
* Office365

In Minemeld the outputs are configured using a `Node` while in Demisto the EDL integration is used.

Coding Notes:
    Any variable naming in which `mm` appears indicates that the value is associated with Minemeld and
    similarly any variable in which `dm` appears indicates that the value is associated with Demisto.
'''


import requests
from typing import Tuple, Set
from netaddr import IPSet, IPNetwork, iprange_to_cidrs

requests.packages.urllib3.disable_warnings()


def get_indicators_list(url: str = '') -> list:
    response = requests.get(url, verify=False)
    indicators_list = response.text.split('\n')
    return indicators_list


def sort_and_format_mm_indicators(indicators: list = []) -> dict:
    print(f'mm indicator lines count: {len(indicators)}')
    cidrs = []
    others = []
    for indicator in indicators:
        if '-' in indicator:
            start, end = indicator.split('-')
            cidrs.extend(iprange_to_cidrs(start, end))
        else:
            others.append(indicator)
    mm_indicators_sorted = {
        'cidrs': cidrs,
        'others': others
    }
    if len(cidrs) >= 1:
        print(f'type:value from `sort_and_format_mm_indicators` -> {type(cidrs[0])}:{cidrs[0]}')
    return mm_indicators_sorted


def sort_and_format_dm_indicators(indicators: list = []) -> dict:
    print(f'dm indicator lines count: {len(indicators)}')
    cidrs = []
    others = []
    for indicator in indicators:
        if '/' in indicator:
            cidrs.append(IPNetwork(indicator))
        else:
            others.append(indicator)
    dm_indicators_sorted = {
        'cidrs': cidrs,
        'others': others
    }
    if len(cidrs) >= 1:
        print(f'type:value from `sort_and_format_dm_indicators` -> {type(cidrs[0])}:{cidrs[0]}')
    return dm_indicators_sorted


def cidrs_compare(dm_cidrs: list = [], mm_cidrs: list = []) -> Tuple[Set, Set, Set, Set]:
    dm_cidrs_set = IPSet(dm_cidrs)
    mm_cidrs_set = IPSet(mm_cidrs)

    # cidrs in both sets
    cidrs_common = dm_cidrs_set.intersection(mm_cidrs_set)

    # cidrs in one set or the other one but not both
    cidrs_different = dm_cidrs_set.symmetric_difference(mm_cidrs_set)

    cidrs_only_in_dm = dm_cidrs_set.difference(mm_cidrs_set)
    cidrs_only_in_mm = mm_cidrs_set.difference(dm_cidrs_set)
    return cidrs_common, cidrs_different, cidrs_only_in_dm, cidrs_only_in_mm


def main():
    dm_indicator_output_url = 'https://ec2-54-194-138-24.eu-west-1.compute.amazonaws.com/instance/execute/EDL_instance_1/'
    mm_indicator_output_url = 'https://ec2-52-16-103-25.eu-west-1.compute.amazonaws.com/feeds/inboundfeedhc'

    # handle demisto indicators
    unformatted_dm_indicators = get_indicators_list(dm_indicator_output_url)
    dm_indicators = sort_and_format_dm_indicators(unformatted_dm_indicators)

    # handle minemeld indicators
    unformatted_mm_indicators = get_indicators_list(mm_indicator_output_url)
    mm_indicators = sort_and_format_mm_indicators(unformatted_mm_indicators)

    dm_cidrs = dm_indicators.get('cidrs')
    mm_cidrs = mm_indicators.get('cidrs')
    cidrs_common, cidrs_different, cidrs_only_in_dm, cidrs_only_in_mm = cidrs_compare(dm_cidrs, mm_cidrs)
    print(f'cidrs_common: {len(cidrs_common.iter_cidrs())}\n'
          f'cidrs_different: {len(cidrs_different.iter_cidrs())}\n'
          f'cidrs_only_in_dm: {len(cidrs_only_in_dm.iter_cidrs())}\n'
          f'cidrs_only_in_mm: {len(cidrs_only_in_mm.iter_cidrs())}')
    # print(f'cidrs_different\n----------\n{cidrs_different}')
    print(f'\ncidrs_only_in_mm\n----------------\n{cidrs_only_in_mm}')
    mm_others = mm_indicators.get('others', [])
    dm_others = dm_indicators.get('others', [])
    print(f'\nothers_in_mm\n------------\n{mm_others}')
    print(f'\nothers_in_dm\n------------\n{dm_others}')


if __name__ == "__main__":
    main()
