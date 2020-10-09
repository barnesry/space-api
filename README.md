# Overview
The purpose of this script is to connect to a Juniper Space Security Director API and retrieve the following detailed configuration in JSON format for the purposes of data export to an external system.

1. Policy Objects
2. Address Objects
3. Service Objects

Once detailed outputs are gathered relating to interesting object types, specific key data is extracted from each verbose output and submitted to an .erb template for each datatype outputting only the key data of interest in json format.

## Usage
`ruby space_api.rb --target 66.129.235.8 --port 45007 --user jcluser`

It is mandatory to supply the ip-address or hostname of the SD server, it's listening port and the username with sufficient authorization to execute the API commands. Password is gathered and obfuscated at the commandline at runtime.

## Output
After parsing, expcted output should be a condensed output depending on the associated .erb templates called within the script.

    {
    "POLICIES": {
        "All Devices Policy Pre": {
            "SOURCE_ZONE": "",
            "DESTINATION_ZONE": "",
        }
        "All Devices Policy Post": {
            "SOURCE_ZONE": "",
            "DESTINATION_ZONE": "",
        }
        "SDK-VSRX_JCL_INITIAL": {
            "SOURCE_ZONE": "",
            "DESTINATION_ZONE": "",
        }
        "ZONE-BASED-POLICY": {
            "SOURCE_ZONE": "untrust",
            "DESTINATION_ZONE": "trust",
        }
    }
    }


    ---------------------------


    {
        "NETWORK_OBJECTS": {
            "Any": {
            "ADDRESS_TYPE": "ANY",
            "IP_ADDRESS": "",
            "DESCRIPTION": "Predefined any address"
            },
            "Any-IPv4": {
            "ADDRESS_TYPE": "ANY_IPV4",
            "IP_ADDRESS": "",
            "DESCRIPTION": "Predefined any-ipv4 address"
            },
            "Any-IPv6": {
            "ADDRESS_TYPE": "ANY_IPV6",
            "IP_ADDRESS": "",
            "DESCRIPTION": "Predefined any-ipv6 address"
            },
            "192.168.150.10/32_metasploitable": {
            "ADDRESS_TYPE": "IPADDRESS",
            "IP_ADDRESS": "192.168.150.10",
            "DESCRIPTION": ""
            },
            "GROUP-METASPLOIT": {
            "ADDRESS_TYPE": "GROUP",
            "IP_ADDRESS": "",
            "DESCRIPTION": ""
            },
            "192.168.150.10/32_metasploit_net": {
            "ADDRESS_TYPE": "NETWORK",
            "IP_ADDRESS": "192.168.150.0/24",
            "DESCRIPTION": ""
            },
            "GROUP-NESTED": {
            "ADDRESS_TYPE": "GROUP",
            "IP_ADDRESS": "",
            "DESCRIPTION": "nested group containing both another group and a host object"
            },
            "server": {
            "ADDRESS_TYPE": "IPADDRESS",
            "IP_ADDRESS": "192.168.1.1",
            "DESCRIPTION": "some random server ip"
            },
        }
    }