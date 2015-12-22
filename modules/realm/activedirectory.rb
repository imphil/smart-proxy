require 'proxy/kerberos'
require 'realm/client'

module Proxy::Realm
  class ActiveDirectory < Client
    include Proxy::Kerberos
    include Proxy::Util

    def initialize
    end

    def check_realm realm
      # FIXME: realm name is currently not set in config. In freeipa it's taken
      #   from the freeipa directory, which is not possible in AD. Don't check
      #   or also take from config?
      #raise Proxy::Realm::Error.new "Unknown realm #{realm}" unless realm.casecmp(@realm_name).zero?
    end

    def create realm, params
      check_realm realm

      # most likely also contains
      # hostname and userclass
      # see app/models/concerns/orchestration/realm.rb
      if params[:rebuild] == "true"
        logger.warn "AD FIXME: Add support for rebuilding host."
      end

      fqdn = params[:hostname]
      host = fqdn.split('.')[0]
      domain = fqdn.split('.')[1..-1].join('.').downcase

      # get domain-specific configuration
      raise Proxy::Realm::Error.new "No configuration found for the domain." unless Proxy::Realm::Plugin.settings.ad_domain_mapping.key?(domain)

      domain_config = Proxy::Realm::Plugin.settings.ad_domain_mapping[domain]
      logger.info "AD: Using configuration for domain #{domain}. "
      logger.info "AD: base_ou = #{domain_config['base_ou']}"
      logger.info "AD: computername_prefix = #{domain_config['computername_prefix']}"
      logger.info "AD: keytab = #{domain_config['keytab']}"
      logger.info "AD: principal = #{domain_config['principal']}"

      # kinit: get krb5 token
      errors = []
      errors << "keytab not configured" unless domain_config['keytab']
      errors << "keytab not found: #{domain_config['keytab']}" unless domain_config['keytab'] && File.exist?(domain_config['keytab'])
      errors << "principal not configured" unless domain_config['principal']

      if !errors.empty?
        raise Proxy::Realm::Error.new errors.join(", ")
      end

      init_krb5_ccache domain_config['keytab'], domain_config['principal']

      # Build computername
      # 1) Prefix it, if not already prefixed (required by some corporate
      #    rules)
      # 2) Limit length to 15 characters, as required by history
      #    (see https://support.microsoft.com/en-us/kb/909264)
      if host.match(/^#{domain_config['computername_prefix']}/i)
        computername = host
      else
        computername = domain_config['computername_prefix'] + host
      end
      computername = computername[0, 15]
      logger.debug "AD: Using computername #{computername}"

      # create account in AD
      cmd_args = []
      cmd_args << '--precreate'
      cmd_args << "--realm #{escape_for_shell(realm)}"
      cmd_args << "--hostname #{escape_for_shell(fqdn)}"
      cmd_args << "--description 'Foreman managed client'"
      cmd_args << "--upn 'host/#{escape_for_shell(fqdn)}'"
      cmd_args << "--service host"
      cmd_args << "--computer-name #{escape_for_shell(computername)}"
      cmd_args << "--base #{escape_for_shell(domain_config['base_ou'])}"

      cmd = "/usr/sbin/msktutil #{cmd_args.join(' ')} 2>&1"
      logger.info "AD: Executing '#{cmd}' to add host to directory."

      response = %x{#{cmd}}
      logger.debug "AD: msktutil response: #{response}" unless response.empty?

      raise Proxy::Realm::Error.new "msktutil failed with return code #{$?.exitstatus}" unless $?.exitstatus == 0

      result = {"result" => {"message" => "computer account for host #{fqdn} added to active directory"}}
      JSON.pretty_generate(result["result"])
    end

    def delete realm, hostname
      check_realm realm
      logger.warn "AD FIXME: Add support for rebuilding host."

      result = {"result" => {"message" => "Currently not implemented. Delete host manually in AD."}}
      JSON.pretty_generate(result)
    end
  end
end
