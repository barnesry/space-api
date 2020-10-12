'''
MIT License

Copyright (c) 2020 Ryan Barnes

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

class Server
    attr_accessor :verbose

    def initialize(host, port, username, password)
        @base_url = "https://" + host + ":" + port + "/"
        puts "Using server base URL : " + @base_url if @verbose
        @auth_header = build_auth_header(username, password)
        # pp("AuthHeader : " + @auth_header.inspect)
        @verbose = false
    end

    def login
        @login_url = '/api/space/user-management/login'
        @login_uri = URI(@base_url + @login_url)

        # setup our HTTPS session to Security Director
        @https = Net::HTTP.new(@login_uri.host, @login_uri.port)
        @https.use_ssl = true    # apparently not required in newer versions of net/http
        @https.verify_mode = OpenSSL::SSL::VERIFY_NONE if @https.use_ssl? # turn off cert checking
        
        # open the https session
        @https.start()
        
        # build our login request
        @request = Net::HTTP::Post.new(@login_uri)
        @request["Authorization"] = @auth_header

        @response = @https.request @request
        # puts @response.code
        # puts @response.body
        
        # save our login cookies if we successfully logged in
        case @response
        when Net::HTTPSuccess, Net::HTTPRedirection
            
            puts "LOGIN SUCCESS!!"
            # save our session cookies JSESSIONIDSSO/JSESSIONID needed to retrieve policies
            @all_cookies = @response.get_fields('Set-Cookie')
            @cookies_array = Array.new
            
            @all_cookies.each do |cookie|
                @cookies_array.push(cookie.split('; ')[0])
            end



            @cookies = @cookies_array.join('; ')  
            # pp("Cookie : #{@cookies}")
        else 
            puts "LOGIN FAILED : #{@response.value}"
        end

    end

    def logout
        puts "Session state : #{@https.active?}"
        puts "Done... Closing."
        @https.finish()
        puts "Session state : #{@https.active?}"

    end

    def get_policies
        # make our call to retrieve policies
        @policies_url = '/api/juniper/sd/policy-management/firewall/policies'
        @uri = URI(@base_url + @policies_url)
        @request = Net::HTTP::Get.new(@uri)
        @request["Authorization"] = @auth_header
        @request["Accept"] = 'application/vnd.juniper.sd.policy-management.firewall.policies+json;version=2;q=0.02'
        @request["Cookie"] = @cookies

        @response = @https.request @request
        #puts @https.inspect
        #puts @response.code
        #puts @response.body
        policies = JSON.parse(@response.body)
        return policies
    end

    def get_policy_by_name(policy_name)
        # make our call to retrieve policies
        @policies_url = '/api/juniper/sd/policy-management/firewall/policies'
        @filter = "?filter=(name eq '#{policy_name}')"
        @uri = URI(@base_url + @policies_url + @filter)
        puts @uri
        @request = Net::HTTP::Get.new(@uri)
        @request["Authorization"] = @auth_header
        @request["Accept"] = 'application/vnd.juniper.sd.policy-management.firewall.policies+json;version=2;q=0.02'
        @request["Cookie"] = @cookies

        @response = @https.request @request
        #puts @https.inspect
        #puts @response.code
        #puts @response.body
        policies = JSON.parse(@response.body)
        return policies
    end

    def get_detailed_policy_by_name(policy_name)
        # make our call to retrieve policies
        @policy = get_policy_by_name(policy_name)
        #pp(@policy)
        @policy_id = @policy["policies"]["policy"][0]["id"]

        @detailed_policies_url = "/api/juniper/sd/policy-management/firewall/policies/detailedPolicy/#{@policy_id}"
        @uri = URI(@base_url + @detailed_policies_url)
        puts @uri
        @request = Net::HTTP::Get.new(@uri)
        @request["Authorization"] = @auth_header
        @request["Accept"] = 'application/vnd.juniper.sd.policy-management.firewall.policy+json;version=2;q=0.02'
        @request["Cookie"] = @cookies

        @response = @https.request @request
        #puts @https.inspect
        #puts @response.code
        #puts @response.body
        policies = JSON.parse(@response.body)
        return policies
    end

    def get_policy_and_rules_by_policy_name(policy_name)
        # first get the policy
        @policy = get_policy_by_name(policy_name)
        pp(@policy)
        @policy_id = @policy["policies"]["policy"][0]["id"]

        # get our rule IDs
        @rule_ids = get_rules_by_policy(policy_name)

        # get our rules by rule-group-type (zone vs global)
        @rules = get_rules_by_rule_group_type(policy_name)

        @rule_ids.each do |rule_id|
            @rules_url = "/api/juniper/sd/policy-management/firewall/policies/#{@policy_id}/rules/#{rule_id}"
            @uri = URI(@base_url + @rules_url)
            puts @uri

            @request = Net::HTTP::Get.new(@uri)
            @request["Authorization"] = @auth_header
            @request["Accept"] = 'application/vnd.juniper.sd.policy-management.firewall.rule+json;version=2;q=0.02'
            @request["Cookie"] = @cookies
            @response = @https.request @request

            case @response
            when Net::HTTPSuccess, Net::HTTPRedirection
                @rule = JSON.parse(@response.body)
                pp(@rule)
            else
                puts "REQUEST FAILED : #{@response.value}"
                puts @uri
            end
        end
    end


    def get_rules_by_policy(policy_name)
        # first get the policy
        @policy = get_policy_by_name(policy_name)
        @policy_id = @policy["policies"]["policy"][0]["id"]

        # get rules associated to this policy
        @rules_url = "/api/juniper/sd/policy-management/firewall/policies/#{@policy_id}/rules"
        @uri = URI(@base_url + @rules_url)
        puts @uri

        @rule_ids = []
        @request = Net::HTTP::Get.new(@uri)
        @request["Authorization"] = @auth_header
        @request["Accept"] = 'application/vnd.juniper.sd.policy-management.firewall.rules+json;version=2;q=0.02'
        @request["Cookie"] = @cookies
        @response = @https.request @request

        case @response
        when Net::HTTPSuccess, Net::HTTPRedirection
            @rules = JSON.parse(@response.body)
            @rules["rules"]["rule"].each do |rule|
                @rule_ids.append(rule["id"])
            end

            # return a list of rule group type IDs
            return @rule_ids


        else
            puts "REQUEST FAILED : #{@response.value}"
            puts @uri
        end
    end

    def get_rules_by_rule_group_type(policy_name)
        # first get the policy
        @policy = get_policy_by_name(policy_name)
        @policy_id = @policy["policies"]["policy"][0]["id"]

        # get rule group type IDs for the policy
        @rule_groups = get_rules_by_policy(policy_name)

        # get rules by rule-group-type
        @rule_groups.each do |rule_group_id |
            @rules_url = "/api/juniper/sd/policy-management/firewall/policies/#{@policy_id}/rules/#{rule_group_id}/rules"
            @uri = URI(@base_url + @rules_url)
            puts @uri

            @request = Net::HTTP::Get.new(@uri)
            @request["Authorization"] = @auth_header
            @request["Accept"] = 'application/vnd.juniper.sd.policy-management.firewall.rules+json;version=2;q=0.02'
            @request["Cookie"] = @cookies
            @response = @https.request @request
    
            case @response
            when Net::HTTPSuccess, Net::HTTPRedirection
                @rules = JSON.parse(@response.body)
                # @rules["rules"]["rule"].each do |rule|
                #     @rule_ids.append(rule["id"])
                # end
                pp(@rules)
            else
                puts "REQUEST FAILED : #{@response.value}"
                puts @uri
            end
        end

    end

    def get_addresses
        # make our call to retrieve address objects
        @address_url = '/api/juniper/sd/address-management/v5/address'
        @uri = URI(@base_url + @address_url)
        @request = Net::HTTP::Get.new(@uri)
        @request["Authorization"] = @auth_header
        @request["Accept"] = 'application/json'
        @request["Cookie"] = @cookies

        @response = @https.request @request
        # puts @https.inspect
        # puts @response.code
        # puts @response.body
        addresses = JSON.parse(@response.body)
        return addresses
    end

    def get_detailed_addresses
        # make our call to retrieve address objects
        @address_url = '/api/juniper/sd/address-management/v5/detailed_addresses'
        @uri = URI(@base_url + @address_url)
        @request = Net::HTTP::Get.new(@uri)
        @request["Authorization"] = @auth_header
        @request["Accept"] = 'application/json'
        @request["Cookie"] = @cookies

        @response = @https.request @request
        # puts @https.inspect
        # puts @response.code
        # puts @response.body
        addresses = JSON.parse(@response.body)
        return addresses
    end

    def get_devices
        # make a call to retreive device objects
        @device_url = '/api/juniper/sd/device-management/devices'
        @uri = URI(@base_url + @device_url)
        @request = Net::HTTP::Get.new(@uri)
        @request["Authorization"] = @auth_header
        @request["Accept"] = 'application/vnd.juniper.sd.device-management.devices-extended+json;version=2;q=0.02'
        @request["Cookie"] = @cookies

        @response = @https.request @request
        # puts @https.inspect
        # puts @response.code
        # puts @response.body
        devices = JSON.parse(@response.body)
        return devices
    end

    def devices_in_policy(devices, policies, policy_name)
        # return devices assigned to a specific policy
        devicelist = {policy_name => []}
        devices["devices"]["device"].each do | device |
            if device["assigned-services"]["assigned-service"].any? { |hash| hash["name"] == policy_name }
                devicelist[policy_name].append(device["name"])
            end
        end
        return devicelist
    end

    def get_service_details()
        ''' returns service object details '''
        @service_url = '/api/juniper/sd/service-management/v5/services/details'
        @uri = URI(@base_url + @service_url)
        @request = Net::HTTP::Get.new(@uri)
        @request["Authorization"] = @auth_header
        @request["Accept"] = 'application/json'
        @request["Cookie"] = @cookies

        @response = @https.request @request
        # puts @https.inspect
        # puts @response.code
        # puts @response.body
        @service_details = JSON.parse(@response.body)
        return @service_details
    end
end



class Policy
    ''' Represents attributes of a firewall policy '''
    attr_accessor :name, :from_zone, :to_zone

    def initialize(name, from_zone = nil, to_zone = nil)
        @name       = name
        @from_zone  = from_zone
        @to_zone    = to_zone
    end

    # what we spit out if we try and print the object
    def to_s
        "(PolicyName:#@name, FromZone:#@from_zone, ToZone:#@to_zone)"
    end
end

class Address
    ''' Represents attributes of a network objects '''
    attr_accessor :name, :ip_address, :description, :address_type

    def initialize(name)
        @name   = name
    end

end

class Service
    ''' Represents attributes of a service object '''
    attr_accessor :name, :protocols, :description, :definition_type, :members
    
    def initialize(name)
        @name = name
        @protocols = Array.new
        @members = Array.new
    end

    def add_protocol(protocol)
        @protocols.push(protocol)
    end

    def add_member(service)
        @members.push(service)
    end

end

class Protocol
    ''' Represents attributes of a protocol definition '''
    attr_accessor :name, :dst_port, :description, :protocol_number, :icmp_code, :icmp_type

    def initialize(name)
        @name = name
    end

    @@protocols = { 1 => 'ICMP' ,
                    6 => 'TCP',
                    17 => 'UDP',
                    41 => 'IPv6',
                    47 => 'GRE',
                    50 => 'ESP',
                    58 => 'IPv6 ICMP',
                    88 => 'EIGRP'
                }

    def get_protocol_type
        @@protocols[self.protocol_number]
    end
end