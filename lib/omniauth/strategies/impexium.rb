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
             sync_event_codes: false

      uid { info[:uid] }

      info { raw_user_info }

      def request_phase
        account = Account.find_by(slug: request.params['origin'].gsub(/\//, ''))
        redirect "#{options.client_options.authentication_url}?RedirectUrl=#{callback_url}?slug=#{account.slug}"
      end

      def callback_phase
        self.user_id = request.params['UserId']
        self.sso_token = request.params['sso']
        authenticate
        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + request.params['slug']
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
        return fail!(:invalid_credentials) unless app_response.success?

        credentials = to_json(app_response.body)
        auth_response = Faraday.post(credentials[:uri]) do |request|
          request.headers['Content-Type'] = 'application/json'
          request.headers['AccessToken'] = credentials[:accessToken]
          request.body = auth_request_body
        end
        return fail!(:invalid_credentials) unless auth_response.success?

        data = to_json(auth_response.body)
        self.app_token = data[:appToken]
        self.user_token = data[:userToken]
        self.endpoint_base_url = parse_endpoint_base_url(data[:uri])
      end

      def app_request_body
        MultiJson.dump(
          AppName: options.client_options.client_id,
          AppKey: options.client_options.secret_key
        )
      end

      def auth_request_body
        MultiJson.dump(
          AppId: options.client_options.client_id,
          AppPassword: options.client_options.secret_key,
          appUserEmail: options.client_options.username,
          appUserPassword: options.client_options.password
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

      def raw_user_info
        return @user_info if defined?(@user_info)

        response = connection.get("/api/v1/Individuals/Profile/#{user_id}/1") do |request|
          request.headers['UserToken'] = sso_token
        end
        return fail!(:invalid_credentials) unless response.success?

        data = to_json(response.body)[:dataList].first
        @user_info = {
          uid: data[:id],
          first_name: data[:firstName],
          last_name: data[:lastName],
          email: data[:email]
        }
        @user_info[:access_codes] = access_codes if options.client_options.sync_event_codes
        @user_info
      end

      def registrations_per_page(page)
        response = connection.get("/api/v1/Individuals/#{user_id}/Registrations/#{page}")
        return [] unless response.success?

        data = to_json(response.body)
        data[:dataList].map { |item| item[:event][:code] }
      end

      def parse_endpoint_base_url(uri)
        url = URI.parse(uri)
        "#{url.scheme}://#{url.host}:#{url.port}"
      end

      def to_json(raw)
        MultiJson.load(raw, symbolize_keys: true)
      end
    end
  end
end
