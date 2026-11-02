/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.cache.Cache;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.TestJwks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link DPoPProofReplayValidator}.
 */
public class DPoPProofReplayValidatorTests {

	private static final String INVALID_JTI = "jti claim is invalid or unable to cache.";

	private final DPoPProofReplayValidator.InMemoryCache cache = new DPoPProofReplayValidator.InMemoryCache();

	private final DPoPProofReplayValidator replayValidator = new DPoPProofReplayValidator(this.cache);

	@Test
	public void constructorWhenCacheNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DPoPProofReplayValidator(null))
				.withMessage("cache cannot be null");
		// @formatter:on
	}

	@Test
	public void setClockSkewWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.replayValidator.setClockSkew(null))
				.withMessage("clockSkew cannot be null");
		// @formatter:on
	}

	@Test
	public void setClockSkewWhenNegativeThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.replayValidator.setClockSkew(Duration.ofSeconds(-1)))
				.withMessage("clockSkew must be >= 0");
		// @formatter:on
	}

	@Test
	public void setClockWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.replayValidator.setClock(null))
				.withMessage("clock cannot be null");
		// @formatter:on
	}

	@Test
	public void setMaxSizeWhenZeroThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.cache.setMaxSize(0))
				.withMessage("maxSize must be > 0");
		// @formatter:on
	}

	@Test
	public void setMaxRequestsPerKeyWhenZeroThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.cache.setMaxRequestsPerKey(0))
				.withMessage("maxRequestsPerKey must be > 0");
		// @formatter:on
	}

	@Test
	public void validateWhenJtiMissingThenFailure() {
		Jwt dPoPProof = dPoPProof(TestJwks.DEFAULT_RSA_JWK).issuedAt(Instant.now()).build();
		assertFailure(this.replayValidator.validate(dPoPProof), "jti claim is required.");
	}

	@Test
	public void validateWhenIatMissingThenFailure() {
		Jwt dPoPProof = dPoPProof(TestJwks.DEFAULT_RSA_JWK).jti(UUID.randomUUID().toString()).build();
		assertFailure(this.replayValidator.validate(dPoPProof), "iat claim is required.");
	}

	@Test
	public void validateWhenIatBeforeTimeWindowThenFailure() {
		Instant now = Instant.now();
		this.replayValidator.setClock(Clock.fixed(now, ZoneOffset.UTC));
		Instant issuedAt = now.minus(Duration.ofSeconds(31));
		Jwt dPoPProof = dPoPProof(TestJwks.DEFAULT_RSA_JWK, UUID.randomUUID().toString(), issuedAt);
		assertFailure(this.replayValidator.validate(dPoPProof), "iat claim is invalid.");
	}

	@Test
	public void validateWhenIatAfterTimeWindowThenFailure() {
		Instant now = Instant.now();
		this.replayValidator.setClock(Clock.fixed(now, ZoneOffset.UTC));
		Instant issuedAt = now.plus(Duration.ofSeconds(31));
		Jwt dPoPProof = dPoPProof(TestJwks.DEFAULT_RSA_JWK, UUID.randomUUID().toString(), issuedAt);
		assertFailure(this.replayValidator.validate(dPoPProof), "iat claim is invalid.");
	}

	@Test
	public void validateWhenJwkMissingThenFailure() {
		// @formatter:off
		Jwt dPoPProof = Jwt.withTokenValue("dpop-proof")
				.header("typ", "dpop+jwt")
				.header("alg", "RS256")
				.jti(UUID.randomUUID().toString())
				.issuedAt(Instant.now())
				.build();
		// @formatter:on
		assertFailure(this.replayValidator.validate(dPoPProof), "jwk header is missing or invalid.");
	}

	@Test
	public void validateWhenJtiAlreadyUsedThenFailure() {
		Jwt dPoPProof = dPoPProof(TestJwks.DEFAULT_RSA_JWK, UUID.randomUUID().toString(), Instant.now());
		assertThat(this.replayValidator.validate(dPoPProof).hasErrors()).isFalse();
		assertFailure(this.replayValidator.validate(dPoPProof), INVALID_JTI);
	}

	@Test
	public void validateWhenCacheFullThenFailureAndUsedJtiNotEvicted() {
		this.cache.setMaxSize(1);
		Jwt dPoPProof = dPoPProof(TestJwks.DEFAULT_RSA_JWK, UUID.randomUUID().toString(), Instant.now());
		assertThat(this.replayValidator.validate(dPoPProof).hasErrors()).isFalse();
		// Attempt to evict the used jti by flooding the cache
		Jwt floodDPoPProof = dPoPProof(TestJwks.DEFAULT_EC_JWK, UUID.randomUUID().toString(), Instant.now());
		assertFailure(this.replayValidator.validate(floodDPoPProof), INVALID_JTI);
		// Replay is still rejected
		assertFailure(this.replayValidator.validate(dPoPProof), INVALID_JTI);
		assertThat((Map<?, ?>) this.cache.getNativeCache()).hasSize(1);
	}

	@Test
	public void validateWhenMaxRequestsPerKeyReachedThenFailure() {
		this.cache.setMaxRequestsPerKey(2);
		for (int i = 0; i < 2; i++) {
			Jwt dPoPProof = dPoPProof(TestJwks.DEFAULT_RSA_JWK, UUID.randomUUID().toString(), Instant.now());
			assertThat(this.replayValidator.validate(dPoPProof).hasErrors()).isFalse();
		}
		Jwt floodDPoPProof = dPoPProof(TestJwks.DEFAULT_RSA_JWK, UUID.randomUUID().toString(), Instant.now());
		assertFailure(this.replayValidator.validate(floodDPoPProof), INVALID_JTI);
		// DPoP Proofs signed with another key are not affected
		Jwt otherDPoPProof = dPoPProof(TestJwks.DEFAULT_EC_JWK, UUID.randomUUID().toString(), Instant.now());
		assertThat(this.replayValidator.validate(otherDPoPProof).hasErrors()).isFalse();
		assertThat((Map<?, ?>) this.cache.getNativeCache()).hasSize(3);
	}

	@Test
	public void validateWhenValidThenJtiCachedUntilIssuedAtPlusClockSkew() throws Exception {
		Cache mockCache = mock(Cache.class);
		DPoPProofReplayValidator mockCacheReplayValidator = new DPoPProofReplayValidator(mockCache);
		mockCacheReplayValidator.setClockSkew(Duration.ofSeconds(10));
		Instant issuedAt = Instant.now();
		Jwt dPoPProof = dPoPProof(TestJwks.DEFAULT_RSA_JWK, UUID.randomUUID().toString(), issuedAt);
		assertThat(mockCacheReplayValidator.validate(dPoPProof).hasErrors()).isFalse();
		// @formatter:off
		ArgumentCaptor<DPoPProofReplayValidator.CacheValue> cacheValueCaptor =
				ArgumentCaptor.forClass(DPoPProofReplayValidator.CacheValue.class);
		// @formatter:on
		verify(mockCache).putIfAbsent(anyString(), cacheValueCaptor.capture());
		DPoPProofReplayValidator.CacheValue cacheValue = cacheValueCaptor.getValue();
		String jwkThumbprint = TestJwks.DEFAULT_RSA_JWK.toPublicJWK().computeThumbprint().toString();
		assertThat(cacheValue.getIssuedAt()).isEqualTo(issuedAt);
		assertThat(cacheValue.getExpiresAt()).isEqualTo(issuedAt.plus(Duration.ofSeconds(10)));
		assertThat(cacheValue.getJwkThumbprint()).isEqualTo(jwkThumbprint);
	}

	private static Jwt dPoPProof(JWK jwk, String jti, Instant issuedAt) {
		return dPoPProof(jwk).jti(jti).issuedAt(issuedAt).build();
	}

	private static Jwt.Builder dPoPProof(JWK jwk) {
		// @formatter:off
		return Jwt.withTokenValue("dpop-proof")
				.header("typ", "dpop+jwt")
				.header("alg", "RS256")
				.header("jwk", jwk.toPublicJWK().toJSONObject())
				.claim("htm", "GET")
				.claim("htu", "https://resource1");
		// @formatter:on
	}

	private static void assertFailure(OAuth2TokenValidatorResult result, String description) {
		assertThat(result.hasErrors()).isTrue();
		OAuth2Error error = result.getErrors().iterator().next();
		assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_DPOP_PROOF);
		assertThat(error.getDescription()).isEqualTo(description);
	}

}
