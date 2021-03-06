package ru.ratauth.server.handlers

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.ObjectMapper
import groovy.util.logging.Slf4j
import io.netty.handler.codec.http.HttpResponseStatus
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component
import ratpack.error.ServerErrorHandler
import ratpack.handling.Context
import ratpack.http.MediaType
import ru.ratauth.exception.AuthorizationException
import ru.ratauth.exception.BaseAuthServerException
import ru.ratauth.exception.ExpiredException
import ru.ratauth.exception.IdentifiedException
import ru.ratauth.server.handlers.readers.ReadRequestException
import ru.ratauth.utils.ExceptionUtils

/**
 * @author mgorelikov
 * @since 19/11/15
 */
@Slf4j
@Component
class AuthErrorHandler implements ServerErrorHandler {
  @Autowired
  ObjectMapper jacksonObjectMapper

  public static final int AUTHENTICATION_TIMEOUT = 419
  public static final int MAX_EXCEPTION_DEPTH = 10

  @Override
  void error(Context context, Throwable throwable) throws Exception {
    def exception = ExceptionUtils.getThrowable(throwable, BaseAuthServerException.class, MAX_EXCEPTION_DEPTH)

    if (exception in ExpiredException.class)
      sendIdentifiedError(context, AUTHENTICATION_TIMEOUT, exception)
    else if (exception in ReadRequestException.class)
      sendIdentifiedError(context, HttpResponseStatus.BAD_REQUEST.code(), exception)
    else if (exception in AuthorizationException.class)
      sendIdentifiedError(context, HttpResponseStatus.FORBIDDEN.code(), exception)
    else if(exception)
      sendError(context, HttpResponseStatus.INTERNAL_SERVER_ERROR.code(), exception)
    else
      sendError(context, HttpResponseStatus.INTERNAL_SERVER_ERROR.code(), throwable)
  }

  private static void sendError(Context context, int code, Throwable throwable) {
    context.response.status(code)
    context.response.send(throwable.getMessage())
    log.error("Auth error: ", throwable)
  }

  private void sendIdentifiedError(Context context, int code, IdentifiedException exception) {
    context.response.status(code)
    context.response.contentType(MediaType.APPLICATION_JSON)
    def dto = jacksonObjectMapper.writeValueAsString(new ExceptionDTO(exception))
    log.error(dto, exception)
    context.response.send(MediaType.APPLICATION_JSON, dto)
  }

  private class ExceptionDTO {
    @JsonProperty("base_id")
    final String baseId
    @JsonProperty("type_id")
    final String typeId
    final String id
    final Map<String,String> message;
    @JsonProperty("class")
    final String clazz;

    private static final String DEFAULT_LANG = "en"

    ExceptionDTO(IdentifiedException exception) {
      this.baseId = exception.baseId
      this.typeId = exception.typeId
      this.id = exception.id
      clazz = exception.getClass().toString()
      message = [(DEFAULT_LANG): exception.getMessage()] as Map
    }
  }
}
