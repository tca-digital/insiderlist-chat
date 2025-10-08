# frozen_string_literal: true

module PortalAuthentication
  extend ActiveSupport::Concern

  included do
    before_action :authenticate_portal_access!, if: :portal_requires_authentication?
  end

  private

  def portal_requires_authentication?
    ENV['PORTAL_JWT_SECRET'].present?
  end

  def authenticate_portal_access!
    return if valid_portal_session?

    redirect_to_login
  end

  def valid_portal_session?
    token = extract_portal_token
    return false if token.blank?

    if verify_portal_token(token)
      true
    else
      # Even if token is expired, store tenant info for redirect
      store_tenant_from_expired_token(token)
      false
    end
  end

  def extract_portal_token
    # Try cookie first, then Authorization header
    cookies[:portal_auth_token] || 
      request.headers['Authorization']&.gsub(/^Bearer\s+/, '')
  end

  def verify_portal_token(token)
    jwt_secret = ENV.fetch('PORTAL_JWT_SECRET', nil)
    return false if jwt_secret.blank?

    decoded = JWT.decode(
      token,
      jwt_secret,
      true,
      { algorithm: 'HS256', verify_expiration: true }
    )
    
    @current_portal_user = decoded[0]
    true
  rescue JWT::DecodeError, JWT::ExpiredSignature
    false
  end

  def redirect_to_login
    login_path = ENV.fetch('PORTAL_LOGIN_URL', nil)
    
    if login_path.present?
      login_url = build_login_url(login_path)
      if login_url.present?
        redirect_to "#{login_url}?next=#{CGI.escape(request.fullpath)}"
        return
      end
    end
    
    # Show error if we can't determine where to redirect
    render 'public/api/v1/portals/error/401', status: :unauthorized, layout: 'portal'
  end

  def build_login_url(login_path)
    # If it's already a full URL, use it as-is
    return login_path if login_path.start_with?('http://', 'https://')
    
    # Try to get tenant domain from stored session or referrer
    base_url = session[:portal_tenant_domain] || extract_domain_from_referrer
    
    if base_url.present?
      "#{base_url.chomp('/')}#{login_path}"
    else
      # Fallback: show error instead of breaking
      nil
    end
  end

  def extract_domain_from_referrer
    return nil unless request.referrer.present?
    
    uri = URI.parse(request.referrer)
    "#{uri.scheme}://#{uri.host}#{':' + uri.port.to_s if uri.port && ![80, 443].include?(uri.port)}"
  rescue URI::InvalidURIError
    nil
  end

  def store_tenant_from_expired_token(token)
    jwt_secret = ENV.fetch('PORTAL_JWT_SECRET', nil)
    return if jwt_secret.blank?

    # Decode without verification to get tenant info
    decoded = JWT.decode(token, nil, false)
    tenant_domain = decoded[0]['tenant_domain']
    session[:portal_tenant_domain] = tenant_domain if tenant_domain.present?
  rescue StandardError
    nil
  end
end

