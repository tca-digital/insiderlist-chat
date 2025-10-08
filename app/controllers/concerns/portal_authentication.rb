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
    # Show error page - users must access from their tenant subdomain
    if set_portal_for_error
      render 'public/api/v1/portals/error/401', status: :unauthorized, layout: 'portal'
    else
      render inline: simple_401_html, status: :unauthorized
    end
  end

  def simple_401_html
    <<~HTML
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authentication Required</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { font-family: system-ui, -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: #f9fafb; }
          .container { text-align: center; padding: 2rem; }
          .emoji { font-size: 4rem; margin-bottom: 1rem; }
          h1 { font-size: 2rem; color: #1f2937; margin: 0 0 0.5rem; }
          p { color: #6b7280; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="emoji">🔒</div>
          <h1>Authentication Required</h1>
          <p>Please access the help center from your account.</p>
        </div>
      </body>
      </html>
    HTML
  end

  def set_portal_for_error
    @portal = Portal.find_by(slug: params[:slug], archived: false) if params[:slug].present?
    return false if @portal.nil?
    
    @locale = params[:locale] || @portal.default_locale
    @is_plain_layout_enabled = params[:show_plain_layout] == 'true'
    @theme_from_params = params[:theme] if %w[dark light].include?(params[:theme])
    true
  end
end

