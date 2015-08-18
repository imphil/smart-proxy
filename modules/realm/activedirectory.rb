require 'proxy/kerberos'
require 'realm/client'

module Proxy::Realm
  class ActiveDirectory < Client
    include Proxy::Kerberos
    include Proxy::Util

    def initialize
      errors = []
      errors << "keytab not configured"                      unless Proxy::Realm::Plugin.settings.realm_keytab
      errors << "keytab not found: #{Proxy::Realm::Plugin.settings.realm_keytab}" unless Proxy::Realm::Plugin.settings.realm_keytab && File.exist?(Proxy::Realm::Plugin.settings.realm_keytab)
      errors << "principal not configured"                   unless Proxy::Realm::Plugin.settings.realm_principal

      logger.info "AD: realm keytab is '#{Proxy::Realm::Plugin.settings.realm_keytab}' and using principal '#{Proxy::Realm::Plugin.settings.realm_principal}'"

      if errors.empty?
        # Get krb5 token
        init_krb5_ccache Proxy::Realm::Plugin.settings.realm_keytab, Proxy::Realm::Plugin.settings.realm_principal
      else
        raise Proxy::Realm::Error.new errors.join(", ")
      end
    end

    def check_realm realm
      # FIXME: realm name is currently not set in config. In freeipa it's taken
      #   from the freeipa directory, which is not possible in AD. Don't check
      #   or also take from config?
      #raise Proxy::Realm::Error.new "Unknown realm #{realm}" unless realm.casecmp(@realm_name).zero?
    end

    def create realm, params
      check_realm realm

      if params[:rebuild] == "true"
        logger.warn "FIXME: Add support for rebuilding host."
      end

      fqdn = params[:hostname]
      host = fqdn.split('.')[0]
      domain = fqdn.split('.')[1..-1].join('.').downcase

      cmd_args = []
      cmd_args << '--precreate'
      cmd_args << "--realm #{escape_for_shell(realm)}"
      cmd_args << "--hostname #{escape_for_shell(fqdn)}"
      cmd_args << "--description 'Foreman managed client'"
      cmd_args << "--upn 'host/#{escape_for_shell(fqdn)}'"

      if Proxy::Realm::Plugin.settings.ad_domain_mapping.key?(domain)
        domain_config = Proxy::Realm::Plugin.settings.ad_domain_mapping[domain]
        logger.info "AD: Using configuration for domain #{domain}. "
        logger.info "AD: base_ou = #{domain_config['base_ou']}"
        logger.info "AD: computername_prefix = #{domain_config['computername_prefix']}"

        cmd_args.push("--computer-name #{escape_for_shell(domain_config['computername_prefix'] + host)}")
        cmd_args.push("--base #{escape_for_shell(domain_config['base_ou'])}")
      else
        logger.info "AD: Not using any domain-specific configuration."

        cmd_args.push("--computer-name #{escape_for_shell(domain_config['computername_prefix'] + host)}")
      end

      cmd = "/usr/sbin/msktutil #{cmd_args.join(' ')} 2>&1"
      logger.info "AD: Executing '#{cmd}' to add host to directory."

      response = %x{#{cmd}}
      logger.debug "msktutil response: #{response}" unless response.empty?

      raise Proxy::Realm::Error.new "msktutil failed with return code #{$?.exitstatus}" unless $?.exitstatus == 0

      result = {"result" => {"message" => "computer account for host #{fqdn} added to active directory"}}
      JSON.pretty_generate(result["result"])
    end

    def delete realm, hostname
      check_realm realm
      logger.warn "FIXME: Add support for rebuilding host."

      result = {"result" => {"message" => "Currently not implemented. Delete host manually in AD."}}
      JSON.pretty_generate(result)
    end
  end
end
