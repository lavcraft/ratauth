package ru.ratauth.server.handlers.readers

import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import ratpack.http.Headers
import ratpack.util.MultiValueMap
import ru.ratauth.interaction.AuthzRequest
import ru.ratauth.interaction.AuthzResponseType
import ru.ratauth.interaction.GrantType

import static ru.ratauth.server.handlers.readers.RequestUtil.*

/**
 * @author djassan
 * @since 06/11/15
 */
@CompileStatic
@Slf4j
class AuthzRequestReader {
  private static final String RESPONSE_TYPE = "response_type"
  private static final String GRANT_TYPE = "grant_type"
  private static final String CLIENT_ID = "client_id"
  private static final String SCOPE = "scope"
  private static final String REDIRECT_URI = "redirect_uri"
  private static final String REFRESH_TOKEN = "refresh_token"
  private static
  final Set<String> BASE_FIELDS = new HashSet<String>(Arrays.asList(RESPONSE_TYPE, CLIENT_ID, SCOPE, REDIRECT_URI, REFRESH_TOKEN, GRANT_TYPE));

  static AuthzRequest readAuthzRequest(MultiValueMap<String, String> params, Headers headers) {
    log.debug('Reading auth request\nparams:' + params.toMapString() + '\nheaders:'+headers.asMultiValueMap().toMapString())
    AuthzResponseType responseType = extractEnumField(params, RESPONSE_TYPE, true, AuthzResponseType.class)
    GrantType grantType = extractEnumField(params, GRANT_TYPE, false, GrantType.class)

    def builder = AuthzRequest.builder()
        .responseType(responseType)
        .redirectURI(extractField(params, REDIRECT_URI, false))

    if (GrantType.AUTHENTICATION_TOKEN == grantType) {
      if (responseType == AuthzResponseType.TOKEN) {
        throw new ReadRequestException("Response for that grant_type could not contain token")
      }
      def auth = extractAuth(headers)
      builder.clientId(auth[0])
          .clientSecret(auth[1])
      builder.refreshToken(extractField(params, REFRESH_TOKEN, true))
      builder.externalClientId(extractField(params, CLIENT_ID, true))
      builder.grantType(grantType)
      builder.scopes(extractField(params, SCOPE, true).split(" ").toList())
    } else if (responseType == AuthzResponseType.TOKEN) {
      def auth = extractAuth(headers)
      builder.clientId(auth[0])
          .clientSecret(auth[1])
      def scope = extractField(params, SCOPE, false)?.split(" ")?.toList()
      if(scope)
        builder.scopes(scope)
    } else {
      builder.clientId(extractField(params, CLIENT_ID, true))
      def scope = extractField(params, SCOPE, false)?.split(" ")?.toList()
      if(scope)
        builder.scopes(scope)
    }
    builder.authData(extractRest(params, BASE_FIELDS))
    builder.build()
  }
}
