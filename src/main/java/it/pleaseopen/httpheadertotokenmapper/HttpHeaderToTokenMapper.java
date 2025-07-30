package it.pleaseopen.httpheadertotokenmapper;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;

public class HttpHeaderToTokenMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper, TokenIntrospectionTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String PROVIDER_ID = "scopes-data-mapper";

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName("http-header");
        property.setLabel("HTTP header");
        property.setHelpText("The HTTP header to parse.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        // The builtin protocol mapper let the user define under which claim name (key)
        // the protocol mapper writes its value. To display this option in the generic dialog
        // in keycloak, execute the following method.
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        // The builtin protocol mapper let the user define for which tokens the protocol mapper
        // is executed (access token, id token, user info). To add the config options for the different types
        // to the dialog execute the following method. Note that the following method uses the interfaces
        // this token mapper implements to decide which options to add to the config. So if this token
        // mapper should never be available for some sort of options, e.g. like the id token, just don't
        // implement the corresponding interface.
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, HttpHeaderToTokenMapper.class);
    }

    @Override
    public AccessToken transformAccessToken(AccessToken accessToken, ProtocolMapperModel protocolMapperModel, KeycloakSession keycloakSession, UserSessionModel userSessionModel, ClientSessionContext clientSessionContext) {
        String header = protocolMapperModel.getConfig().get("http-header");

        if (header == null || header.trim().isEmpty()) return accessToken;

        if(keycloakSession.getContext().getHttpRequest().getHttpHeaders().getRequestHeader(header).size() == 0){
            return accessToken;
        }
        OIDCAttributeMapperHelper.mapClaim(accessToken, protocolMapperModel, keycloakSession.getContext().getHttpRequest().getHttpHeaders().getRequestHeader(header).get(0));
        return accessToken;
    }

    @Override
    public IDToken transformIDToken(IDToken idToken, ProtocolMapperModel protocolMapperModel, KeycloakSession keycloakSession, UserSessionModel userSessionModel, ClientSessionContext clientSessionContext){
        String header = protocolMapperModel.getConfig().get("http-header");

        if (header == null || header.trim().isEmpty()) return idToken;

        if(keycloakSession.getContext().getHttpRequest().getHttpHeaders().getRequestHeader(header).size() == 0){
            return idToken;
        }
        OIDCAttributeMapperHelper.mapClaim(idToken, protocolMapperModel, keycloakSession.getContext().getHttpRequest().getHttpHeaders().getRequestHeader(header).get(0));
        return idToken;
    }

    @Override
    public AccessToken transformUserInfoToken(AccessToken accessToken, ProtocolMapperModel protocolMapperModel, KeycloakSession keycloakSession, UserSessionModel userSessionModel, ClientSessionContext clientSessionContext) {
        String header = protocolMapperModel.getConfig().get("http-header");

        if (header == null || header.trim().isEmpty()) return accessToken;

        if(keycloakSession.getContext().getHttpRequest().getHttpHeaders().getRequestHeader(header).size() == 0){
            return accessToken;
        }
        OIDCAttributeMapperHelper.mapClaim(accessToken, protocolMapperModel, keycloakSession.getContext().getHttpRequest().getHttpHeaders().getRequestHeader(header).get(0));
        return accessToken;
    }

    @Override
    public AccessToken transformIntrospectionToken(AccessToken accessToken, ProtocolMapperModel protocolMapperModel, KeycloakSession keycloakSession, UserSessionModel userSessionModel, ClientSessionContext clientSessionContext) {
        String header = protocolMapperModel.getConfig().get("http-header");

        if (header == null || header.trim().isEmpty()) return accessToken;

        if(keycloakSession.getContext().getHttpRequest().getHttpHeaders().getRequestHeader(header).size() == 0){
            return accessToken;
        }
        OIDCAttributeMapperHelper.mapClaim(accessToken, protocolMapperModel, keycloakSession.getContext().getHttpRequest().getHttpHeaders().getRequestHeader(header).get(0));
        return accessToken;
    }

    @Override
    public String getDisplayCategory() {
        return "HTTP Header Mapper";
    }

    @Override
    public String getDisplayType() {
        return "HTTP Header Mapper";
    }

    @Override
    public String getHelpText() {
        return "Map an HTTP header to a token claim.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return "POIT-gethttpheader";
    }
}
