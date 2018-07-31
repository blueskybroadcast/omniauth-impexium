require 'omniauth-oauth2'
require 'multi_json'

module OmniAuth
  module Strategies
    class Impexium < OmniAuth::Strategies::OAuth2
      attr_accessor :user_id, :sso_token, :app_token, :user_token, :endpoint_base_url

      option :name, 'impexium'

      option :client_options,
             authentication_url: 'MUST_BE_PROVIDED',
             site: 'MUST_BE_PROVIDED',
             client_id: 'MUST_BE_PROVIDED',
             secret_key: 'MUST_BE_PROVIDED',
             username: 'MUST_BE_PROVIDED',
             password: 'MUST_BE_PROVIDED',
             sync_event_codes: false,
             custom_field_keys: []

      uid { info[:uid] }

      info { raw_user_info }

      def request_phase
        redirect "#{options.client_options.authentication_url}?RedirectUrl=#{callback_url}?slug=#{request.params['origin'].gsub(/\//, '')}"
      end

      def callback_phase
        account = Account.find_by(slug: account_slug)
        @app_event = account.app_events.create(activity_type: 'sso')

        self.user_id = request.params['UserId']
        self.sso_token = request.params['sso']
        authenticate
        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + account.slug
        finalize_app_event
        call_app!
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash
      end

      private

      def access_codes
        codes = []
        1.step do |page|
          codes_per_page = registrations_per_page(page)
          break if codes_per_page.empty?
          codes.concat codes_per_page
        end
        codes
      end

      def authenticate
        app_response = Faraday.post(options.client_options.site) do |request|
          request.headers['Content-Type'] = 'application/json'
          request.body = app_request_body
        end

        app_request_log = "[Impexium] Authenticate App Request:\nPOST #{options.client_options.site}\nRequest body: #{app_request_body(true)}"
        @app_event.logs.create(level: 'info', text: app_request_log)

        if app_response.success?
          app_response_log = "[Impexium] Authenticate App Response (code: #{app_response.status}):\n#{app_response.inspect}"
          @app_event.logs.create(level: 'info', text: app_response_log)

          credentials = to_json(app_response.body)
          auth_response = Faraday.post(credentials[:uri]) do |request|
            request.headers['Content-Type'] = 'application/json'
            request.headers['AccessToken'] = credentials[:accessToken]
            request.body = auth_request_body
          end
          auth_request_log = "[Impexium] Authenticate Request:\nPOST #{credentials[:uri]}\nRequest body: #{auth_request_body(true)}"
          @app_event.logs.create(level: 'info', text: auth_request_log)

          if auth_response.success?
            auth_response_log = "[Impexium] Authenticate Response (code: #{auth_response.status}):\n#{auth_response.inspect}"
            @app_event.logs.create(level: 'info', text: auth_response_log)

            data = to_json(auth_response.body)
            self.app_token = data[:appToken]
            self.user_token = data[:userToken]
            self.endpoint_base_url = parse_endpoint_base_url(data[:uri])
          else
            @app_event.logs.create(level: 'error', text: auth_response_log)
            @app_event.fail!
            fail!(:invalid_credentials)
          end
        else
          @app_event.logs.create(level: 'error', text: app_response_log)
          @app_event.fail!
          fail!(:invalid_credentials)
        end
      end

      def app_request_body(log = false)
        MultiJson.dump(
          AppName: log ? Provider::SECURITY_MASK : options.client_options.client_id,
          AppKey: log ? Provider::SECURITY_MASK : options.client_options.secret_key
        )
      end

      def auth_request_body(log = false)
        MultiJson.dump(
          AppId: log ? Provider::SECURITY_MASK : options.client_options.client_id,
          AppPassword: log ? Provider::SECURITY_MASK : options.client_options.secret_key,
          appUserEmail: log ? Provider::SECURITY_MASK : options.client_options.username,
          appUserPassword: log ? Provider::SECURITY_MASK : options.client_options.password
        )
      end

      def connection
        Faraday.new(url: endpoint_base_url, proxy: options.client_options.proxy_url) do |request|
          request.headers['Content-Type'] = 'application/json'
          request.headers['AppToken'] = app_token
          request.headers['UserToken'] = user_token if user_token
          request.adapter(Faraday.default_adapter)
        end
      end

      def custom_fields_data(parsed_response)
        custom_field_keys = options.client_options.custom_field_keys.to_a
        parsed_response.dig(:customFields).each_with_object({}) do |field, memo|
          next unless custom_field_keys.include?(field[:name])
          memo[field[:name].downcase] = field[:value]
        end
      end

      def raw_user_info
        return @user_info if defined?(@user_info)

        request_log = "[Impexium] Profile Request:\nGET #{endpoint_base_url}/api/v1/Individuals/Profile/#{user_id}/1"
        @app_event.logs.create(level: 'info', text: request_log)

        response = connection.get("/api/v1/Individuals/Profile/#{user_id}/1?IncludeDetails=true") do |request|
          request.headers['UserToken'] = sso_token
        end
        if response.success?
          response_log = "[Impexium] Profile Response (code: #{response.status}):\n#{response.inspect}"
          @app_event.logs.create(level: 'info', text: response_log)

          data = to_json(response.body)[:dataList].first
          @user_info = {
            uid: data[:id],
            first_name: data[:firstName],
            last_name: data[:lastName],
            email: data[:email]
          }
          @user_info[:access_codes] = access_codes if options.client_options.sync_event_codes
          @user_info[:custom_fields_data] = custom_fields_data(data)
          @user_info
        else
          @app_event.logs.create(level: 'error', text: response_log)
          @app_event.fail!
          fail!(:invalid_credentials)
        end

      end

      def registrations_per_page(page)
        request_log = "[Impexium] Registrations Request:\nGET #{endpoint_base_url}/api/v1/Individuals/#{user_id}/Registrations/#{page}"
        @app_event.logs.create(level: 'info', text: request_log)

        response = connection.get("/api/v1/Individuals/#{user_id}/Registrations/#{page}")
        if response.success?
          response_log = "[Impexium] Registrations Response (code: #{response.status}):\n#{response.inspect}"
          @app_event.logs.create(level: 'info', text: response_log)
          data = to_json(response.body)
          data[:dataList].map { |item| item[:event][:code] }
        else
          []
        end
      end

      def parse_endpoint_base_url(uri)
        url = URI.parse(uri)
        "#{url.scheme}://#{url.host}:#{url.port}"
      end

      def to_json(raw)
        MultiJson.load(raw, symbolize_keys: true)
      end

      def account_slug
        request.params['slug']
      end

      def finalize_app_event
        app_event_data = {
          user_info: {
            uid: uid,
            first_name: info[:first_name],
            last_name: info[:last_name],
            email: info[:email]
          }
        }

        @app_event.update(raw_data: app_event_data)
      end
    end
  end
end
