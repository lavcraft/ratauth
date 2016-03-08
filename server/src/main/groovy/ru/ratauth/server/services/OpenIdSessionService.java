package ru.ratauth.server.services;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ru.ratauth.entities.*;
import ru.ratauth.server.secutiry.OAuthIssuerImpl;
import ru.ratauth.server.secutiry.TokenProcessor;
import ru.ratauth.server.secutiry.UUIDValueGenerator;
import ru.ratauth.server.utils.DateUtils;
import ru.ratauth.services.SessionService;
import rx.Observable;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * @author djassan
 * @since 17/02/16
 */
@Slf4j
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class OpenIdSessionService implements AuthSessionService {
  private final SessionService sessionService;
  private final TokenProcessor tokenProcessor;
  private final TokenCacheService tokenCacheService;
  private final OAuthIssuerImpl codeGenerator = new OAuthIssuerImpl(new UUIDValueGenerator());

  @Value("${auth.master_secret}")
  private String masterSecret;//final

  @Override
  public Observable<Session> initSession(RelyingParty relyingParty, Map<String, Object> userInfo, Set<String> scopes,
                                         String redirectUrl) {
    final LocalDateTime now = LocalDateTime.now();
    return createSession(relyingParty, userInfo, scopes, redirectUrl, now, null);
  }

  @Override
  public Observable<Session> createSession(RelyingParty relyingParty, Map<String, Object> userInfo, Set<String> scopes,
                                           String redirectUrl) {
    final LocalDateTime now = LocalDateTime.now();
    final LocalDateTime tokenExpires = now.plus(relyingParty.getTokenTTL(), ChronoUnit.SECONDS);
    final Token token = Token.builder()
        .token(codeGenerator.accessToken())
        .expiresIn(DateUtils.fromLocal(tokenExpires))
        .created(DateUtils.fromLocal(now))
        .build();
    return createSession(relyingParty, userInfo, scopes, redirectUrl, now, token);
  }

  private Observable<Session> createSession(RelyingParty relyingParty, Map<String, Object> userInfo, Set<String> scopes,
                                            String redirectUrl, LocalDateTime now, Token token) {
    final LocalDateTime sessionExpires = now.plus(relyingParty.getSessionTTL(), ChronoUnit.SECONDS);
    final LocalDateTime refreshExpires = now.plus(relyingParty.getRefreshTokenTTL(), ChronoUnit.SECONDS);
    final LocalDateTime authCodeExpires = now.plus(relyingParty.getCodeTTL(), ChronoUnit.SECONDS);

    final String subject = tokenCacheService.extractSubject(userInfo);
    final String jwtInfo = tokenProcessor.createToken(masterSecret, null,
        DateUtils.fromLocal(now), DateUtils.fromLocal(sessionExpires),
        tokenCacheService.extractAudience(scopes), scopes, subject, userInfo);

    final AuthEntry authEntry = AuthEntry.builder()
        .created(DateUtils.fromLocal(now))
        .authCode(codeGenerator.authorizationCode())
        .codeExpiresIn(DateUtils.fromLocal(authCodeExpires))
        .refreshToken(codeGenerator.refreshToken())
        .refreshTokenExpiresIn(DateUtils.fromLocal(refreshExpires))
        .scopes(scopes)
        .relyingParty(relyingParty.getName())
        .authType(AuthType.COMMON)
        .redirectUrl(redirectUrl)
        .build();
    authEntry.addToken(token);
    final Session session = Session.builder()
        .identityProvider(relyingParty.getIdentityProvider())
        .status(Status.ACTIVE)
        .created(DateUtils.fromLocal(now))
        .expiresIn(DateUtils.fromLocal(sessionExpires))
        .userInfo(jwtInfo)
        .entries(new HashSet<>(Arrays.asList(authEntry)))
        .build();
    return sessionService.create(session)
        .doOnNext(sess -> logSession(subject, relyingParty.getName()));
  }

  @Override
  public Observable<Boolean> addToken(Session session, RelyingParty relyingParty) {
    final LocalDateTime now = LocalDateTime.now();
    final LocalDateTime tokenExpires = now.plus(relyingParty.getTokenTTL(), ChronoUnit.SECONDS);
    final Token token = Token.builder()
        .token(codeGenerator.accessToken())
        .expiresIn(DateUtils.fromLocal(tokenExpires))
        .created(DateUtils.fromLocal(now))
        .build();
    return sessionService.addToken(session.getId(), relyingParty.getName(), token)
        .doOnNext(subs -> session.getEntry(relyingParty.getName()).ifPresent(entry -> entry.addToken(token)));
  }

  @Override
  public Observable<Session> addEntry(Session session, RelyingParty relyingParty, Set<String> scopes, String redirectUrl) {
    final LocalDateTime now = LocalDateTime.now();
    final LocalDateTime refreshExpires = now.plus(relyingParty.getRefreshTokenTTL(), ChronoUnit.SECONDS);
    final LocalDateTime authCodeExpires = now.plus(relyingParty.getCodeTTL(), ChronoUnit.SECONDS);
    final AuthEntry authEntry = AuthEntry.builder()
        .created(DateUtils.fromLocal(now))
        .authCode(codeGenerator.authorizationCode())
        .codeExpiresIn(DateUtils.fromLocal(authCodeExpires))
        .refreshToken(codeGenerator.refreshToken())
        .refreshTokenExpiresIn(DateUtils.fromLocal(refreshExpires))
        .scopes(scopes)
        .relyingParty(relyingParty.getName())
        .authType(AuthType.CROSS)
        .redirectUrl(redirectUrl)
        .build();
    session.getEntries().add(authEntry);
    return sessionService.addEntry(session.getId(), authEntry)
        .map(res -> session);
  }

  @Override
  public Observable<Session> getByValidCode(String code, Date now) {
    return sessionService.getByValidCode(code, now);
  }

  @Override
  public Observable<Session> getByValidRefreshToken(String token, Date now) {
    return sessionService.getByValidRefreshToken(token, now);
  }

  @Override
  public Observable<Session> getByValidToken(String token, Date now) {
    return sessionService.getByValidToken(token, now);
  }

  private static void logSession(String subject, String relyingParty) {
    log.info("Created session by relyingParty: " + relyingParty + " for subject: " + subject);
  }
}
