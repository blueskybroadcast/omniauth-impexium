RSpec.describe OmniAuth::Strategies::Impexium do
  let(:log) { double }
  let(:options) do
    {
      client_options: {
        site: 'https://public.impexium/Api/v1/WebApiUrl',
        sync_event_codes: true,
        membertype_sync: true,
        custom_field_keys: ['City', 'Zip']
      }
    }
  end
  let(:info) do
    {
      uid: '666',
      first_name: 'Bender',
      last_name: 'Rodriguez',
      email: 'bender@planet.express',
      expiration_date: '2018-02-16T15:08:03.429Z',
      access_codes: ['GNC2016', 'ANNUAL2016'],
      member_type: 'ACT',
      custom_fields_data: { 'city' => 'New New York', 'zip' => '12345' }
    }
  end

  subject { described_class.new('app_id', 'secret', options) }

  before do
    stub_const('Provider::SECURITY_MASK', '[FILTERED]')
    allow(@app_event).to receive(:logs).and_return(log)
    allow(log).to receive(:create).and_return(true)
  end

  describe '#options' do
    describe '#name' do
      it { expect(subject.options.name).to be_eql('impexium') }
    end

    describe '#client_options' do
      describe '#authentication_url' do
        it { expect(subject.options.client_options.authentication_url).to be_eql('MUST_BE_PROVIDED') }
      end

      describe '#site' do
        it { expect(subject.options.client_options.site).to be_eql('https://public.impexium/Api/v1/WebApiUrl') }
      end

      describe '#client_id' do
        it { expect(subject.options.client_options.client_id).to be_eql('MUST_BE_PROVIDED') }
      end

      describe '#secret_key' do
        it { expect(subject.options.client_options.secret_key).to be_eql('MUST_BE_PROVIDED') }
      end

      describe '#password' do
        it { expect(subject.options.client_options.password).to be_eql('MUST_BE_PROVIDED') }
      end

      describe '#sync_event_codes' do
        it { expect(subject.options.client_options.password).to be_truthy }
      end

      describe '#membertype_sync' do
        it { expect(subject.options.client_options.membertype_sync).to be_truthy }
      end

      describe '#custom_field_keys' do
        it { expect(subject.options.client_options.custom_field_keys).to be_eql(['City', 'Zip']) }
      end
    end
  end

  describe '#info' do
    before do
      allow(subject).to receive(:raw_user_info).and_return(info)
    end

    context 'first_name' do
      it { expect(subject.info[:first_name]).to be_eql('Bender') }
    end

    context 'last_name' do
      it { expect(subject.info[:last_name]).to be_eql('Rodriguez') }
    end

    context 'email' do
      it { expect(subject.info[:email]).to be_eql('bender@planet.express') }
    end

    context 'access_codes' do
      it { expect(subject.info[:access_codes]).to be_eql(['GNC2016', 'ANNUAL2016']) }
    end

    context 'custom_fields_data' do
      it { expect(subject.info[:custom_fields_data]).to be_eql({'city' => 'New New York', 'zip' => '12345'}) }
    end

    context 'expiration_date' do
      it { expect(subject.info[:expiration_date]).to be_eql('2018-02-16T15:08:03.429Z') }
    end
  end

  describe '#authenticate' do
    before do
      stub_authentication_requests
      subject.send(:authenticate)
    end

    it 'assigns end_point_base_url' do
      expect(subject.endpoint_base_url).to be_eql('http://inta.impexium:80')
    end

    it 'assigns app_token' do
      expect(subject.app_token).to be_eql('fc7e78c1-fb72-4a9a-a66f-d8c62579c347')
    end

    it 'assigns user_token' do
      expect(subject.user_token).to be_eql('ca626840-f9eb-0135-b1e6-1801a78efc2d')
    end
  end

  describe '#raw_user_info' do
    before do
      subject.user_id = '7257fb90-f7a7-0135-b1a9-1801a78efc2d'
      subject.sso_token = '7a2667f0-f7a7-0135-b1a9-1801a78efc2d'
      subject.app_token = 'fc7e78c1-fb72-4a9a-a66f-d8c62579c347'
      subject.endpoint_base_url = 'http://inta.impexium:80'
      stub_user_info_requests
    end

    it { expect(subject.send(:raw_user_info)).to eq info }
  end
end

def response_fixture(filename)
  IO.read("spec/fixtures/#{filename}.json")
end

def stub_authentication_requests
  stub_request(:post, 'https://public.impexium/Api/v1/WebApiUrl')
    .with(body: "{\"AppName\":\"MUST_BE_PROVIDED\",\"AppKey\":\"MUST_BE_PROVIDED\"}")
    .to_return(status: 200, body: response_fixture('web_api_url'))
  stub_request(:post, "http://public.impexium/api/v1/signup/authenticate")
    .with(body: "{\"AppId\":\"MUST_BE_PROVIDED\",\"AppPassword\":\"MUST_BE_PROVIDED\",\"appUserEmail\":\"MUST_BE_PROVIDED\",\"appUserPassword\":\"MUST_BE_PROVIDED\"}", headers: {'Accesstoken'=>'43b53917-d0fa-45fc-9eb5-3ed79edc4e7e'})
    .to_return(status: 200, body: response_fixture('authenticate'), headers: {})
end

def stub_user_info_requests
  stub_request(:get, 'http://inta.impexium/api/v1/Individuals/Profile/7257fb90-f7a7-0135-b1a9-1801a78efc2d/1?IncludeDetails=true')
    .with(headers: { 'UserToken' => '7a2667f0-f7a7-0135-b1a9-1801a78efc2d' })
    .to_return(status: 200, body: response_fixture('profile'), headers: {})
  stub_request(:get, "http://inta.impexium/api/v1/Individuals/7257fb90-f7a7-0135-b1a9-1801a78efc2d/Registrations/1")
    .to_return(status: 200, body: response_fixture('registrations'), headers: {})
  stub_request(:get, "http://inta.impexium/api/v1/Individuals/7257fb90-f7a7-0135-b1a9-1801a78efc2d/Registrations/2")
    .to_return(status: 200, body: MultiJson.dump(dataList: []), headers: {})
end
