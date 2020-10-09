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
require 'optparse'
require'net/http'
require 'json'
require 'pp'
require 'erb'
require 'base64'
require 'highline/import'
require 'logger'
require_relative 'space_class.rb'

verbose = false


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
    # get SD password from the commandline masking input
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
optparse = OptionParser.new do |opts|
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
end

begin
    optparse.parse!
    # enforce presense of host, port, user
    mandatory = [:host, :port, :user]
    # for each mandatory param, return only those which aren't defined
    missing = mandatory.select{ |param| options[param].nil? }
    unless missing.empty?
      raise OptionParser::MissingArgument.new(missing.join(', '))
    end
  rescue OptionParser::InvalidOption, OptionParser::MissingArgument
    puts $!.to_s
    puts optparse
    exit
  end
  
  puts "Performing task with options: #{options.inspect}"

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


pp(s.get_service_details())


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



