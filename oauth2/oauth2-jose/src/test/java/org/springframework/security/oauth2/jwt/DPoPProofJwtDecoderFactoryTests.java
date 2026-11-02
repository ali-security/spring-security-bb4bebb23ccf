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

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link DPoPProofJwtDecoderFactory}.
 *
 * @author Joe Grandja
 */
public class DPoPProofJwtDecoderFactoryTests {

	private JWKSource<SecurityContext> jwkSource;

	private NimbusJwtEncoder jwtEncoder;

	private DPoPProofJwtDecoderFactory jwtDecoderFactory = new DPoPProofJwtDecoderFactory();

	@BeforeEach
	public void setUp() {
		this.jwkSource = mock(JWKSource.class);
		this.jwtEncoder = new NimbusJwtEncoder(this.jwkSource);
	}

	@Test
	public void setJwtValidatorFactoryWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.jwtDecoderFactory.setJwtValidatorFactory(null))
			.withMessage("jwtValidatorFactory cannot be null");
	}

	@Test
	public void createDecoderWhenContextNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.jwtDecoderFactory.createDecoder(null))
			.withMessage("dPoPProofContext cannot be null");
	}

	@Test
	public void decodeWhenJoseTypeInvalidThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("invalid-type")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("JOSE header typ (type) invalid-type not allowed");
	}

	@Test
	public void decodeWhenJwkMissingThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
//				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("Missing jwk parameter in JWS Header.");
	}

	@Test
	public void decodeWhenMethodInvalidThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method("POST")		// Mismatch
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("The htm claim is not valid");
	}

	@Test
	public void decodeWhenTargetUriInvalidThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri("https://resource2")		// Mismatch
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("The htu claim is not valid");
	}

	@Test
	public void decodeWhenJtiMissingThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
//				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("jti claim is required");
	}

	@Test
	public void decodeWhenJtiAlreadyUsedThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		jwtDecoder.decode(dPoPProofContext.getDPoPProof());
		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("jti claim is invalid");
	}

	@Test
	public void decodeWhenIatMissingThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
//				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("iat claim is required");
	}

	@Test
	public void decodeWhenIatBeforeTimeWindowThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		Instant issuedAt = Instant.now().minus(Duration.ofSeconds(65));		// now minus 65 seconds
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(issuedAt)
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("iat claim is invalid");
	}

	@Test
	public void decodeWhenIatAfterTimeWindowThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		Instant issuedAt = Instant.now().plus(Duration.ofSeconds(65));		// now plus 65 seconds
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(issuedAt)
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("iat claim is invalid");
	}

	@Test
	public void decodeWhenDPoPProofValidThenDecoded() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);
		jwtDecoder.decode(dPoPProof.getTokenValue());
	}

	@Test
	public void createDefaultJwtValidatorFactoryWhenValidatorsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> DPoPProofJwtDecoderFactory.createDefaultJwtValidatorFactory(null))
				.withMessage("validators cannot be null");
		// @formatter:on
	}

	@Test
	public void decodeWhenIatOutsideReplayWindowThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		Instant issuedAt = Instant.now().minus(Duration.ofSeconds(45));		// now minus 45 seconds
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(issuedAt)
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		// @formatter:off
		assertThatExceptionOfType(BadJwtException.class)
				.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
				.withMessageContaining("iat claim is invalid");
		// @formatter:on
	}

	@Test
	public void decodeWhenJtiCacheFloodedThenReplayedDPoPProofRejected() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		Jwt dPoPProof = encodeDPoPProof(this.jwtEncoder, rsaJwk, method, targetUri);

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);
		jwtDecoder.decode(dPoPProof.getTokenValue());

		// Flood the jti cache with DPoP Proofs signed with another key
		ECKey floodJwk = new ECKeyGenerator(Curve.P_256).keyID("flood-ec-jwk-kid").generate();
		JWKSource<SecurityContext> floodJwkSource = mock(JWKSource.class);
		given(floodJwkSource.get(any(), any())).willReturn(Collections.singletonList(floodJwk));
		NimbusJwtEncoder floodJwtEncoder = new NimbusJwtEncoder(floodJwkSource);
		for (int i = 0; i < 1000; i++) {
			Jwt floodDPoPProof = encodeDPoPProof(floodJwtEncoder, floodJwk, method, targetUri);
			jwtDecoder.decode(floodDPoPProof.getTokenValue());
		}

		// Replay the DPoP Proof
		// @formatter:off
		assertThatExceptionOfType(BadJwtException.class)
				.isThrownBy(() -> jwtDecoder.decode(dPoPProof.getTokenValue()))
				.withMessageContaining("jti claim is invalid");
		// @formatter:on
	}

	@Test
	public void decodeWhenDPoPProofInvalidThenJtiNotCached() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		DPoPProofReplayValidator.InMemoryCache cache = new DPoPProofReplayValidator.InMemoryCache();
		cache.setMaxSize(1);
		List<OAuth2TokenValidator<Jwt>> validators = List.of(new DPoPProofReplayValidator(cache));
		// @formatter:off
		Function<DPoPProofContext, OAuth2TokenValidator<Jwt>> jwtValidatorFactory =
				DPoPProofJwtDecoderFactory.createDefaultJwtValidatorFactory(validators);
		// @formatter:on
		this.jwtDecoderFactory.setJwtValidatorFactory(jwtValidatorFactory);

		String method = "GET";
		String targetUri = "https://resource1";

		Jwt invalidDPoPProof = encodeDPoPProof(this.jwtEncoder, rsaJwk, method, targetUri);

		// @formatter:off
		DPoPProofContext invalidDPoPProofContext = DPoPProofContext.withDPoPProof(invalidDPoPProof.getTokenValue())
				.method(method)
				.targetUri("https://resource2")		// Mismatch
				.build();
		// @formatter:on

		JwtDecoder invalidJwtDecoder = this.jwtDecoderFactory.createDecoder(invalidDPoPProofContext);

		// @formatter:off
		assertThatExceptionOfType(BadJwtException.class)
				.isThrownBy(() -> invalidJwtDecoder.decode(invalidDPoPProof.getTokenValue()))
				.withMessageContaining("The htu claim is not valid");
		// @formatter:on
		assertThat((Map<?, ?>) cache.getNativeCache()).isEmpty();

		Jwt dPoPProof = encodeDPoPProof(this.jwtEncoder, rsaJwk, method, targetUri);

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);
		jwtDecoder.decode(dPoPProof.getTokenValue());
		assertThat((Map<?, ?>) cache.getNativeCache()).hasSize(1);
	}

	@Test
	public void decodeWhenAccessTokenBoundToOtherKeyThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		Jwt dPoPProof = encodeDPoPProof(this.jwtEncoder, rsaJwk, method, targetUri);

		String jwkThumbprint = TestJwks.DEFAULT_EC_JWK.toPublicJWK().computeThumbprint().toString();
		Jwt accessToken = TestJwts.jwt().claim("cnf", Collections.singletonMap("jkt", jwkThumbprint)).build();

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.accessToken(accessToken)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		// @formatter:off
		assertThatExceptionOfType(BadJwtException.class)
				.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
				.withMessageContaining("jkt claim is invalid");
		// @formatter:on
	}

	private static Jwt encodeDPoPProof(NimbusJwtEncoder jwtEncoder, JWK jwk, String method, String targetUri) {
		SignatureAlgorithm algorithm = (jwk instanceof ECKey) ? SignatureAlgorithm.ES256 : SignatureAlgorithm.RS256;
		// @formatter:off
		JwsHeader jwsHeader = JwsHeader.with(algorithm)
				.type("dpop+jwt")
				.jwk(jwk.toPublicJWK().toJSONObject())
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on
		return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));
	}

}
