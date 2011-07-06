require 'omniauth/oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    # OAuth 2.0 based authentication with WePay. In order to
    # sign up for an application, you need to [register an application](https://wepay.com/developer/register)
    # and provide the proper credentials to this middleware.
    #
    # Authenticate to WePay utilizing OAuth 2.0 and retrieve
    # basic user information.
    #
    # @example Basic Usage
    #     use OmniAuth::Strategies::WePay, 'client ID', 'client secret'
    class WePay < OmniAuth::Strategies::OAuth2
      # @param [Rack Application] app standard middleware application argument
      # @param [String] client_id the application ID for your client
      # @param [String] client_secret the application secret
      # @option options [Hash]
      #   :scope - the application permissions you are requesting. Defaults to all.
      #            [manage_accounts,view_balance,collect_payments,refund_payments,view_user]
      def initialize(app, client_id=nil, client_secret=nil, options={}, &block)
        client_options = {
          :authorize_url => 'https://stage.wepay.com/v2/oauth2/authorize',
          :token_url => 'https://stage.wepay.com/v2/oauth2/token'
        }
        super(app, :wepay, client_id, client_secret, client_options, options, &block)
      end

      protected

      def user_data
        @data ||= MultiJson.decode(@access_token.get('https://stage.wepay.com/v2/user').body)
      end

      def request_phase
        options[:scope] ||= "manage_accounts,view_balance,collect_payments,refund_payments,view_user"
        super
      end

      def user_info
        {
          'email' => user_data['email'],
          'name' => "#{user_data['first_name']} #{user_data['last_name']}",
          'first_name' => user_data['first_name'],
          'last_name' => user_data['last_name']
        }
      end

      def auth_hash
        OmniAuth::Utils.deep_merge(super, {
          'uid' => @access_token.params['user_id'],
          'user_info' => user_info,
          'extra' => {
            'user_hash' => user_data,
            'token_type' => @access_token.params['token_type']
          }
        })
      end
    end
  end
end
