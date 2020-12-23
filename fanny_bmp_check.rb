##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
class MetasploitModule < Msf::Post

        include Msf::Post::Common
        include Msf::Post::Windows::Registry

        def initialize(info={})
                super( update_info( info,
                                 'Name' => 'FannyBMP Registry Check',
                                 'Description' => %q{This module searches for the Fanny.bmp worm related registry keys},
                                 'License' => MSF_LICENSE,
                                 'Author' => [ 'William M.'],
                                 'Platform' => [ 'win' ],
                                 'SessionTypes' => [ 'meterpreter','shell'], 
                                 'References' => [[ 'URL', 'https://securelist.com/a-fanny-equation-i-am-your-father-stuxnet/68787' ]]  # Change this <--  to shorter url
                        ))
                                      # Include these in the docs : []
                                      #https://fmnagisa.wordpress.com/2020/08/27/revisiting-equationgroups-fanny-worm-or-dementiawheel/ 
                                      #https://securelist.com/a-fanny-equation-i-am-your-father-stuxnet/68787 Too long for a Ref. URL <-- shorten this one []

        end
        
        def run
                                        # https://securelist.com/a-fanny-equation-i-am-your-father-stuxnet/68787
                                query =    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\"ECELP4",'
                                query += 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\Driver,'
                                query += 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\filter2,'
                                query += 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\filter3,'
                                query += 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\filter8'
                                # make some O.  Improvements here []  |\|
                match = 0

                                # Is changed: [×]
                                #                         ...on #{sysinfo['Computer']} for...
                                print_status("Searching registry on Target for Fanny.bmp artifacts.")
                keys = query.split(/,/)
                begin 
                        keys.each do |key|
                                (key, value) = parse_query(key)
                                has_key = registry_enumkeys(key)
                                has_val = registry_enumvals(key)

                                if has_key.include?(value) || has_val.include?(value)
                                        
                                 # Is changed: [×]
                                 #           ...on #{sysinfo['Computer']} for...
                                        print_good("Target #{key}\\#{value} found in registry.")                                                                                                                                                                                               
                                        match += 1                                                                                                                                                                                                                                                              
                                end                                                                                                                                                                                                                                                                             
                        end                                                                                                                                                                                                                                                                                     
                rescue; end                                                                                                                                                                                                                                                                                     

                # Is changed: [×]
                #           ...on #{sysinfo['Computer']} for...
                print_status("Target #{match} result(s) found in registry.")
        end

        def parse_query(key)
                path = key.split("\\")
                value = path[-1]
                path.pop
                key = path.join("\\")
                return key, value
        end

end 
       
