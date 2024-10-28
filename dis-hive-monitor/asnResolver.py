#
# This software is made available according to the terms in the LICENSE.txt accompanying this code
#

import re
import logging
import pprint


class AsnResolver:
    def __init__(self, args):
        self.int_name_regex = re.compile(args.int_name_regex) if args.int_name_regex else None
        self.int_name_lookup_file = args.int_name_lookup_file
        self.int_desc_regex = re.compile(args.int_desc_regex) if args.int_desc_regex else None
        self.int_desc_lookup_file = args.int_desc_lookup_file
        self.int_name_ruleset = None
        self.int_desc_ruleset = None
        self.logger = logging.getLogger("ASN Resolver")
        self.logger.info(f"Initialized with {pprint.pformat(self.__dict__)}")

    def router_interface_to_asn(self, router_name, int_name, int_description):
        self.logger.debug(f"router_interface_to_asn({router_name}, {int_name}, {int_description})")
        if int_name:
            if self.int_name_regex:
                match = self.int_name_regex.match(int_name)
                if match:
                    return int(match.group(1))
            if self.int_name_ruleset:
                raise NotImplementedError("ASN interface name rulesets not supported (yet)")
        if int_description:
            if self.int_desc_regex:
                match = self.int_desc_regex.match(int_description)
                if match:
                    return int(match.group(1))
            if self.int_desc_ruleset:
                raise NotImplementedError("ASN interface description rulesets not supported (yet)")
        return None
