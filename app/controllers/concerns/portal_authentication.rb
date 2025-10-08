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
    # Check for valid JWT token in cookie or header
    token = extract_portal_token
    return false if token.blank?

    verify_portal_token(token)
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
      redirect_to "#{login_url}?next=#{CGI.escape(request.fullpath)}"
    else
      render 'public/api/v1/portals/error/401', status: :unauthorized, layout: 'portal'
    end
  end

  def build_login_url(login_path)
    # If it's already a full URL, use it as-is
    return login_path if login_path.start_with?('http://', 'https://')
    
    # For relative paths, use the referrer's domain
    referrer = request.referrer
    if referrer.present?
      uri = URI.parse(referrer)
      "#{uri.scheme}://#{uri.host}#{':' + uri.port.to_s if uri.port && ![80, 443].include?(uri.port)}#{login_path}"
    else
      # Fallback to relative path
      login_path
    end
  end
end

