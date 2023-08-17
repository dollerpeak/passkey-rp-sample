/*
 * Copyright (C) 2023 SK TELECOM CO., LTD.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.sktelecom.authentication.passkey.passkeyrpsample.service;

import com.sktelecom.authentication.fido2.server.dto.authentication.AuthenticationOptionsServerRequestDto;
import com.sktelecom.authentication.fido2.server.dto.authentication.AuthenticationResultDto;
import com.sktelecom.authentication.fido2.server.dto.authentication.AuthenticationResultsServerRequestDto;
import com.sktelecom.authentication.fido2.server.dto.common.ChallengeDto;
import com.sktelecom.authentication.fido2.server.dto.common.CredentialStatusDto;
import com.sktelecom.authentication.fido2.server.dto.common.ServerResponseDto;
import com.sktelecom.authentication.fido2.server.dto.credential.CredentialIdDto;
import com.sktelecom.authentication.fido2.server.dto.credential.CredentialIdListResponseDto;
import com.sktelecom.authentication.fido2.server.dto.credential.CredentialInfoListResponseDto;
import com.sktelecom.authentication.fido2.server.dto.credential.CredentialInfoResponseDto;
import com.sktelecom.authentication.fido2.server.dto.credential.CredentialStatusUpdateDto;
import com.sktelecom.authentication.fido2.server.dto.registration.RegistrationOptionsServerRequestDto;
import com.sktelecom.authentication.fido2.server.dto.registration.RegistrationResultDto;
import com.sktelecom.authentication.fido2.server.dto.registration.RegistrationResultsServerRequestDto;
import com.sktelecom.authentication.passkey.passkeyrpsample.configuration.WebAuthnProperties;
import com.sktelecom.authentication.passkey.passkeyrpsample.configuration.WebAuthnProperties.WebauthnServerProperties;
import com.sktelecom.authentication.passkey.passkeyrpsample.model.transport.AttestationOptionsServerRequest;

import lombok.extern.slf4j.Slf4j;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.hierarchicalroles.CycleInRoleHierarchyException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

/**
 * {@inheritDoc}
 *
 * Implementation for RP REST Client
 */
@Component
@Slf4j
public class WebAuthnRpRestClientImpl implements WebAuthnRpRestClient {
    // rest template for WebAuthn server
    private final RestTemplate restTemplate;
    private String registrationRequestUrl;
    private String registrationResponseUrl;
    private String authenticationRequestUrl;
    private String authenticationResponseUrl;
    private String userUrl;
    private String userCredentialUrl;
    private String userCredentialsUrl;
    
    

    public WebAuthnRpRestClientImpl(WebAuthnProperties webauthnProperties, RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
        // initialize Webauthn server URLs
        initializeRequestUrls(webauthnProperties.getServer());
    }

    @Override
    public ServerResponseDto<ChallengeDto> getRegistrationOptions(RegistrationOptionsServerRequestDto request) {
    	log.info("WebAuthnRpRestClientImpl.getRegistrationOptions()====================");
    	log.info("==> request = " + request);
    	log.info("==> registrationRequestUrl = " + registrationRequestUrl);
    	log.info("==> restTemplate = " + restTemplate.toString());
    	
		// kht /////////////////////////
    	/*
    	request = RegistrationOptionsServerRequestDto(
    				user=UserDto(
    						id=qNQxiuA04BxIprl4PxJRau_z7N3mOQUPCsJuLXgZ7wE, 
    						name=louie.houtz@pineappleapple.sr, 
    						displayName=Louie Houtz), 
    				authenticatorSelection=AuthenticatorSelectionCriteriaDto(
    						authenticatorAttachment=cross-platform, 
    						residentKey=null, 
    						userVerification=null), 
    				attestation=direct, 
    				excludeCredentials=true, 
    				timeout=300000)
    	*/
    	
    	/*
    	 access_token
"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3N0Zy1vYXV0aDIuZGFwbGF0Zm9ybS5rciIsInN1YiI6InN0Zy50YW5nby5za3RlbGVjb20uY29tIiwiaWF0IjoxNjkxMTMzMTk2LCJqdGkiOiI0ZDgwYTI0Yi1jMzg5LTRhZTYtYmMxZC05ZTFhYWFkZjkzYzgiLCJjbGllbnRfaWQiOiJzdGcudGFuZ28uc2t0ZWxlY29tLmNvbSIsInNjb3BlIjoicGFzc2tleTpycCIsImF1ZCI6Imh0dHBzOi8vc3RnLXBhc3NrZXkuZGFwbGF0Zm9ybS5rciIsImV4cCI6MTY5MTE0MDM5Nn0.RAu4I_EEXj9VeYIUe4mdkx9vQR74aCssyq3it-3KiSaFQ5Q_2k7BLaWvfWu1MhZnDxatn5ho2yZgo40oWc32UivhCDjv1THmrGfx_BY4uOcaCeUeF1-4gkurbngB6YD1woAA8z-KGnITX6LQTMoLj3ZdIX6ghmXXYEBnARf_Ni9XnJBXzNGTUxkp9TO3LQxgCMSCGb0D9KcCQEAtQTmtJIyBlQ8qA_fpoQvRPS3HQNEGEFkgeueO-_mgAF1WbtoibiWt3CfmGP-4Eje1sUsvAXhzzf1wJNBsSHzZ1CRGdR46L_IbNGtDh7mCNqFhKGv0bv6Uf9A1IvDOXgyKZf3aTg"
    	 */
    	
    	HttpHeaders headers = new HttpHeaders();
		String BEARER_PREFIX = "Bearer ";
		String accessToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3N0Zy1vYXV0aDIuZGFwbGF0Zm9ybS5rciIsInN1YiI6InN0Zy50YW5nby5za3RlbGVjb20uY29tIiwiaWF0IjoxNjkyMjU4MzExLCJqdGkiOiI3MzU0YTI0Zi0wMmRmLTRlOGItODdkYi1iODg3YTJkZmJkZmQiLCJjbGllbnRfaWQiOiJzdGcudGFuZ28uc2t0ZWxlY29tLmNvbSIsInNjb3BlIjoicGFzc2tleTpycCIsImF1ZCI6Imh0dHBzOi8vc3RnLXBhc3NrZXkuZGFwbGF0Zm9ybS5rciIsImV4cCI6MTY5MjI2NTUxMX0.aKciZrvIPN5jbLjQHtl04W87dgImQx1g7-F9DmdaovCF3PY7la6P4iaflxBzxs5gl-oxFKAq3O3pZM6_CrNlcYN11cVAwfyK2zhV5dsx7v0iATeCcZCtcx7zXxobtCEacLVafsyNv2hWYFIyg8f3SVWCgp3xN-dXs-U3gyw4nIoZYLdzegFvNUcB6ohrwYgQdDeUIieKaouQQbCQv38_2QjPIFYiJ_PLD6fm0FsglcXNnUfzM1r3Mq_jw7vgfDq-mqBBsyHJebS-R-6vIO_9pUfy4_XJb5kVfecicXPW5oULasj2_UrvC4H05_TRkEmgwsgEeSmXZastoaFesJSfAw";
		headers.set(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken);		
		String WEBAUTHN_RP_ID = "X-WebAuthentication-RpId";
		headers.set(WEBAUTHN_RP_ID, "stg.tango.sktelecom.com");
		log.info("==> headers = " + headers);
		log.info("==> request = " + request.toString());
		
		ResponseEntity<ServerResponseDto<ChallengeDto>> response =
	            restTemplate.exchange(registrationRequestUrl, HttpMethod.POST, new HttpEntity<>(request, headers),
	                new ParameterizedTypeReference<>() {
	                });
		////////////////////////////////
    	
        // @formatter:off
//        ResponseEntity<ServerResponseDto<ChallengeDto>> response =
//            restTemplate.exchange(registrationRequestUrl, HttpMethod.POST, new HttpEntity<>(request),
//                new ParameterizedTypeReference<>() {
//                });
    	log.info("==> response = " + response);
        log.info("====================WebAuthnRpRestClientImpl.getRegistrationOptions()");
        
        // @formatter:on
        return response.getBody();
    }

    @Override
    public ServerResponseDto<RegistrationResultDto> postRegistrationResponse(RegistrationResultsServerRequestDto request) {
        // @formatter:off
        ResponseEntity<ServerResponseDto<RegistrationResultDto>> response =
            restTemplate.exchange(registrationResponseUrl, HttpMethod.POST, new HttpEntity<>(request),
                new ParameterizedTypeReference<>() {
                });
        // @formatter:on
        return response.getBody();
    }

    @Override
    public ServerResponseDto<ChallengeDto> getAuthenticationOptions(AuthenticationOptionsServerRequestDto request) {
    	log.info("WebAuthnRpRestClientImpl.getAuthenticationOptions()====================");
    	log.info("==> request = " + request);
    	log.info("==> authenticationRequestUrl = " + authenticationRequestUrl);
    	
        // @formatter:off
        ResponseEntity<ServerResponseDto<ChallengeDto>> response =
            restTemplate.exchange(authenticationRequestUrl, HttpMethod.POST, new HttpEntity<>(request),
                new ParameterizedTypeReference<>() {
                });
        
        log.info("==> response = " + response);
        // @formatter:on
        return response.getBody();
    }
    
    // kht
    public void headerTest(HttpRequest request) {
//    	String BEARER_PREFIX = "Bearer ";
//    	OAuth2AuthorizedClientManager manager;
//    	Authentication principal;
//    	ClientRegistration clientRegistration;
//    	
//    	OAuth2AuthorizeRequest oauth2AuthorizeRequest = OAuth2AuthorizeRequest
//                .withClientRegistrationId(clientRegistration.getRegistrationId())
//                .principal(principal)
//                .build();
//    	OAuth2AuthorizedClient client = manager.authorize(oauth2AuthorizeRequest);
//    	request.getHeaders().add(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + client.getAccessToken().getTokenValue());
	}

    @Override
    public ServerResponseDto<AuthenticationResultDto> postAuthenticationResponse(AuthenticationResultsServerRequestDto request) {
        // @formatter:off
        ResponseEntity<ServerResponseDto<AuthenticationResultDto>> response =
            restTemplate.exchange(authenticationResponseUrl, HttpMethod.POST, new HttpEntity<>(request),
                new ParameterizedTypeReference<>() {
                });
        // @formatter:on
        return response.getBody();
    }

    @Override
    public ServerResponseDto<CredentialIdListResponseDto> deleteUser(String userId) {
        // @formatter:off
        ResponseEntity<ServerResponseDto<CredentialIdListResponseDto>> response =
            restTemplate.exchange(userUrl, HttpMethod.DELETE, HttpEntity.EMPTY,
                new ParameterizedTypeReference<>() {
                }, userId);
        // @formatter:on
        return response.getBody();
    }

    @Override
    public ServerResponseDto<CredentialInfoResponseDto> getUserCredential(String userId, String credentialId) {
        // @formatter:off
        ResponseEntity<ServerResponseDto<CredentialInfoResponseDto>> response =
            restTemplate.exchange(userCredentialUrl, HttpMethod.GET, HttpEntity.EMPTY,
                new ParameterizedTypeReference<>() {
                }, userId, credentialId);
        // @formatter:on
        return response.getBody();
    }

    @Override
    public ServerResponseDto<CredentialInfoListResponseDto> getUserCredentials(String userId) {
        // @formatter:off
        ResponseEntity<ServerResponseDto<CredentialInfoListResponseDto>> response =
            restTemplate.exchange(userCredentialsUrl, HttpMethod.GET, HttpEntity.EMPTY,
                new ParameterizedTypeReference<>() {
                }, userId);
        // @formatter:on
        return response.getBody();
    }

    @Override
    public ServerResponseDto<CredentialIdDto> updateCredentialStatus(String userId, String credentialId,
        CredentialStatusDto status) {
        // @formatter:off
        ResponseEntity<ServerResponseDto<CredentialIdDto>> response =
            restTemplate.exchange(userCredentialUrl, HttpMethod.PATCH,
                new HttpEntity<>(new CredentialStatusUpdateDto(status)),
                new ParameterizedTypeReference<>() {
                }, userId, credentialId);
        // @formatter:on
        return response.getBody();
    }

    @Override
    public ServerResponseDto<CredentialIdDto> deleteCredential(String userId, String credentialId) {
        // @formatter:off
        ResponseEntity<ServerResponseDto<CredentialIdDto>> response =
            restTemplate.exchange(userCredentialUrl, HttpMethod.DELETE, HttpEntity.EMPTY,
                new ParameterizedTypeReference<>() {
                }, userId, credentialId);
        // @formatter:on
        return response.getBody();
    }

    private void initializeRequestUrls(WebauthnServerProperties serverProperties) {
        this.registrationRequestUrl = serverProperties.getBaseUrl()
            + serverProperties.getUrlPath().getRegistrationRequest();
        this.registrationResponseUrl = serverProperties.getBaseUrl()
            + serverProperties.getUrlPath().getRegistrationResponse();
        this.authenticationRequestUrl = serverProperties.getBaseUrl()
            + serverProperties.getUrlPath().getAuthenticationRequest();
        this.authenticationResponseUrl = serverProperties.getBaseUrl()
            + serverProperties.getUrlPath().getAuthenticationResponse();
        this.userUrl = serverProperties.getBaseUrl()
            + serverProperties.getUrlPath().getUser();
        this.userCredentialUrl = serverProperties.getBaseUrl()
            + serverProperties.getUrlPath().getUserCredential();
        this.userCredentialsUrl = serverProperties.getBaseUrl()
            + serverProperties.getUrlPath().getUserCredentials();
    }
}
