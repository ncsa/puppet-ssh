# Enable incoming ssh for a given set of hosts
#
# @summary Enable incoming ssh for a given set of hosts
#   + Opens iptables firewall for the hosts
#   + Configures sshd_config with a Match directive and associated parameter
#     settings
#
# @param hostlist
#   Type: Array
#   Desc: list of IPs or Hostnames that are allowed to ssh to this node
#
# @param sshd_cfg_match_params
#   Type: Hash
#   Desc: sshd config keywords and values
#   Format: sshd_cfg_match_params = { 'keyword1' => 'value1',
#                                     'keyword2' => 'value2',
#                                     'keyword3' => [ 'val3_1','val3_2' ],
#                                   }
#
# @example
#   ssh::allow_from { 'comment':
#       'hostlist'         => Array
#       'sshd_cfg_match_params' => Hash
#   }
define ssh::allow_from(
    Array[ String, 1 ]      $hostlist,
    Hash[ String, Data, 1 ] $sshd_cfg_match_params,
) {

    ### FIREWALL
    $hostlist.each | $host | {
        firewall { "222 allow SSH from ${host} for ${name}":
            dport  => 22,
            proto  => tcp,
            source => $host,
            action => accept,
        }
    }


    ### SSHD
    # Defaults
    $config_defaults = {
        'notify' => Service[ sshd ],
    }
    $config_match_defaults = $config_defaults + {
        'position' => 'before first match'
    }

    # Hostnames require "Match Host", IPs/CIDRs require "Match Address"
    # Create separate lists and make two separate match blocks in sshd_config
    # criteria will be either "Host" or "Address"
    # pattern will be the CSV string of hostnames or IPs
    # See also: "sshd_config" man page, for details of criteria-pattern pairs
    $name_list = $hostlist.filter | $elem | { $elem =~ /[a-zA-Z]/ }
    $ip_list   = $hostlist.filter | $elem | { $elem !~ /[a-zA-Z]/ }
    #associate the correct criteria with each list, filter empty lists
    $data = { 'Host'    => $name_list,
              'Address' => $ip_list,
            }.filter | $criteria, $list | {
                size( $list ) > 0
            }
    #loop through data creating a match block for each criteria-pattern
    $data.each | $criteria, $list | {
        $pattern = join( $list, ',' )
        $match_condition = "${criteria} ${pattern}"

        #create match block
        sshd_config_match {
            $match_condition :
            ;
            default: * => $config_match_defaults,
            ;
        }

        #add parameters to the match block
        $sshd_cfg_match_params.each | $key, $val | {
            sshd_config {
                "${match_condition} ${key}" :
                    key       => $key,
                    value     => $val,
                    condition => $match_condition,
                ;
                default: * => $config_defaults,
                ;
            }
        }
    }
}
