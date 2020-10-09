require 'optparse'
require'net/http'
require 'json'
require 'pp'
require 'erb'
require 'base64'
require 'highline/import'
require 'logger'

@@verbose = false

###########
# CLASSES #
###########
class Server
    def initialize(host, port, username, password)
        @base_url = "https://" + host + ":" + port + "/"
        puts "Using server base URL : " + @base_url if @@verbose
        @auth_header = build_auth_header(username, password)
        # pp("AuthHeader : " + @auth_header.inspect)
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

#############
# FUNCTIONS #
#############
def scriptname()
    ''' returns the calling script name minus system path '''
    scriptname = File.basename(__FILE__)
end


def build_base_url(options)
    # take options hash and return base URL for future API calls
    # Example : https://1.1.1.1:8080
    # https assumed for now
    if options[:host] and options[:port]
        base_url = "https://" + options[:host] + ":" + options[:port]
    else
        raise "Missing hostname(--target):port(--port) passed as argument"
    end
end

def build_auth_header(username, password)
    ''' builds the base64 auth_header for http calls '''
    userpass = username + ":" + password
    userpassenc = "Basic " + Base64.encode64(userpass)

    # need to return a string that looks like the following w/o CR/LF
    # "Basic amNsdXNlcjpKdW5pcGVyITE="
    return userpassenc.chomp
end

def get_password(message, mask='*')
    # get SD password from the commandline
    ask(message) { |q| q.echo = mask }
end

def print_policies(detailed_policies)
    # print out the basic policy info
    # why wouldn't the detailedPolicy output include the policyname???
    policy = detailed_policies["policy"]["policy-details"][0]

    sourcezone = policy["source-zone"]["zone"][0]["name"]
    destinationzone = policy["destination-zone"]["zone"][0]["name"]
    puts "#{sourcezone}:#{destinationzone}"

    sourceaddresses = []
    if policy["source-address"]["addresses"].empty?
        sourceaddresses.append("ANY")
    else
        policy["source-address"]["addresses"]["address-reference"].each do |addressrefs|
            addressrefs["address_refs"].each do |address|
                sourceaddresses.append(address["name"])
            end
        end
    end

    destinationaddresses = []
    if policy["destination-address"]["addresses"].empty?
        destinationaddresses.append("ANY")
    else
        policy["destination-address"]["addresses"]["address-reference"].each do |addressrefs|
            addressrefs["address_refs"].each do |address|
                destinationaddresses.append(address["name"])
            end
        end
    end

    puts "SourceAddress : #{sourceaddresses}"
    puts "DestinationAddress : #{destinationaddresses}"
end

def get_to_zone(policy_details)
    ''' returns just the zone name (if present) from the detailed policy output '''
    if !policy_details["policy"]["policy-details"].nil?
        begin
            policy_details["policy"]["policy-details"][0]["destination-zone"]["zone"][0]["name"]
        rescue
            nil
        end
    end
end

def get_from_zone(policy_details)
    ''' returns just the zone name (if present) from the detailed policy output '''
    if !policy_details["policy"]["policy-details"].nil?
        begin
            policy_details["policy"]["policy-details"][0]["source-zone"]["zone"][0]["name"]
        rescue
            nil
        end
    end
end

def get_address_name(detailed_addresses)
    ''' returns just the address name from detailed address API call '''
    begin
        detailed_addresses.each do | address |
            return address.name
        end
    rescue
        return nil
    end
end






##########
## MAIN ##
##########

# set up our logging levels
logger = Logger.new(STDOUT)
logger.level = Logger::WARN

# parse our our command line args
options = {}
OptionParser.new do |opts|
    opts.banner = "Usage : space_sd_classes.rb [options]"

    opts.on("-t", "--target HOST", "Space hostname or IP") do |h|
        options[:host] = h
    end

    opts.on("-p", "--port PORT", "port for SD API") do |p|
        options[:port] = p
    end

    opts.on("-u", "--user USER", "Space SD Username") do |u|
        options[:user] = u
    end

    opts.on("-v", "--verbose", "turn on verbose outputs for debugging") do |v|
        @@verbose = true
        logger.level = Logger::INFO
    end

    opts.on("--help", "Prints this help") do
        puts 
        puts "#{scriptname()} makes SpaceSD API calls to recursively dump policy objects,"
        puts "address objects, and service objects and return specific values in erb"
        puts "JSON formatted templates."
        puts
        puts opts
        exit
    end
end.parse!

logger.info("Options : " + options.inspect)

# Get and check a password from the keyboard
options[:password] = get_password( "SD Password: " )

# setup our server object
s = Server.new(options[:host], 
            options[:port],
            options[:user],
            options[:password],
        )
s.login

# retrieve policy summary
policy_result   = s.get_policies

# address object brief not really needed because we'll call the detailed API call
# address_result  = s.get_addresses

# retrieve detailed address object info instead of brief
detailed_address_result = s.get_detailed_addresses

# retrieve devices associated with the policy
# device_result   = s.get_devices


# build a list of policy objects from the data we get back from the SD API
policies = Array.new()

policy_result["policies"]["policy"].each do | policy | 
    
    # save the policy name
    policy_name = policy["name"]
    
    # perform a detailed policy lookup via the API and policy name to get policy details
    policy_details = s.get_detailed_policy_by_name(policy["name"])
    logger.info(policy_details)

    # grab the to/from zones
    policy_to_zone = get_to_zone(policy_details)
    policy_from_zone = get_from_zone(policy_details)

    # add the policy object with our relevant info to our policy list
    policies.push(Policy.new(name = policy_name, to_zone = policy_to_zone, from_zone = policy_from_zone))

end

# take our policy list we just built with our relevant info and generate our JSON outputs
template = ERB.new(File.read('templates/Policies.json.erb'), 0, trim_mode = '>')
puts template.result_with_hash(policies: policies)

puts
puts
puts "---------------------------"
puts
puts


# enumerate our address objects
addresses = Array.new()
detailed_address_result["output"]["value"].each do | address |
    address_obj = Address.new(name = address["name"])
    
    address_obj.description = address["description"]
    address_obj.address_type = address["address_type"]
        
    if address_obj.address_type == "ANY"
        # don't need to do anything further
    else
        # add the remaining info
        address_obj.ip_address = address["ip_address"]
    end
    
    # add the object to our list of objects
    addresses.push(address_obj)
end

# take our policy list and generate our JSON outputs
template = ERB.new(File.read('templates/NetworkObjects.json.erb'), 0, trim_mode = '>')
puts template.result_with_hash(addresses: addresses)

puts
puts
puts "---------------------------"
puts
puts

#pp(detailed_address_result)





# devices.each do | device |
#     pp(device)
# end

# pp(s.get_policy_by_name("Perimeter vSRX"))
# pp(s.get_policy_and_rules_by_policy_name("Perimeter vSRX"))
# s.get_rules_by_policy("Perimeter vSRX")
# s.get_policy_and_rules_by_policy_name("Perimeter vSRX")
# s.get_rules_by_rule_group_type("Perimeter vSRX")

# puts "Policy : #{POLICYNAME}"
# detailed_policies = s.get_detailed_policy_by_name(POLICYNAME)
# s.logout

# # print our output
# pp(detailed_policies)
# print_policies(detailed_policies)



