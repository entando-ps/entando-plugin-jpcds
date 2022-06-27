/*
 * Copyright 2022-Present Entando S.r.l. (http://www.entando.com) All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */
package org.entando.entando.plugins.jpcds.aps.system.storage;

import com.agiletec.aps.system.EntThreadLocal;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.entando.entando.aps.system.services.storage.BasicFileAttributeView;
import org.entando.entando.aps.system.services.storage.IStorageManager;
import org.entando.entando.aps.system.services.tenant.ITenantManager;
import org.entando.entando.aps.system.services.tenant.TenantConfig;
import org.entando.entando.ent.exception.EntException;
import org.entando.entando.ent.exception.EntRuntimeException;
import org.entando.entando.ent.util.EntLogging.EntLogFactory;
import org.entando.entando.ent.util.EntLogging.EntLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.util.Base64Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

/**
 * @author E.Santoboni
 */
public class CdsStorageManager implements IStorageManager {
    
    private static final EntLogger logger = EntLogFactory.getSanitizedLogger(CdsStorageManager.class);
    
    private static final String PRIMARY_CODE = "PRIMARY_CODE";
    
    private static final String CDS_PUBLIC_URL_TENANT_PARAM = "cdsPublicUrl";
    private static final String CDS_PRIVATE_URL_TENANT_PARAM = "cdsPrivateUrl";
    private static final String CDS_PATH_TENANT_PARAM = "cdsPath";
    
    private static final String URL_SEP = "/";
    
    private static final String SECTION_PUBLIC = "public";
    private static final String SECTION_PRIVATE = "protected";
    
    private static final String WRONG_PATH_NAME = "Wrong_path";
    
    private String cdsPublicUrl;
    private String cdpPrivateUrl;
    private String cdsPath;
    private String kcAuthUrl;
    private String kcRealm;
    private String kcClientId;
    private String kcClientSecret;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    private Map<String, String> tenantsToken = new HashMap<>();
    
    private ITenantManager tenantManager;
    
    @Override
    public String getBaseResourceUrl(boolean isProtected) {
        return this.getCdsPublicUrl();
    }

    @Override
    public void saveFile(String subPath, boolean isProtectedResource, InputStream is) throws EntException, IOException {
        try {
            TenantConfig config = this.getTenantConfig();
            InputStreamResource resource = new InputStreamResource(is);
            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            body.add("file", resource);
            body.add("protected", isProtectedResource);
            body.add("path", subPath);
            String url = String.format("%s/upload/", this.extractCdsBaseUrl(config, true));
            String result = this.executePostCall(url, body, config, false);
            System.out.println("*********************************");
            System.out.println(result);
            System.out.println("*********************************");
        } catch (Exception e) {
            logger.error("Error saving file", e);
            throw new EntException("Error saving file", e);
        }
    }
    
    private String executePostCall(String url, MultiValueMap<String, Object> body, TenantConfig config, boolean force) {
        try {
            HttpHeaders headers = this.getBaseHeader(Arrays.asList(MediaType.ALL), config, force);
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);
            HttpEntity<MultiValueMap<String, Object>> entity = new HttpEntity<>(body, headers);
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<String> responseEntity = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
            return responseEntity.getBody();
        } catch (HttpClientErrorException e) {
            if (!force && (e.getStatusCode().equals(HttpStatus.UNAUTHORIZED))) {
                return this.executePostCall(url, body, config, true);
            } else {
                throw new EntRuntimeException("Invalid POST, response status " + e.getStatusCode() + " - url " + url);
            }
        }
    }

    @Override
    public boolean deleteFile(String subPath, boolean isProtectedResource) throws EntException {
        try {
            TenantConfig config = this.getTenantConfig();
            String section = this.getSection(isProtectedResource);
            String subPathFixed = (!StringUtils.isBlank(subPath)) ? (subPath.trim().startsWith(URL_SEP) ? subPath.trim().substring(1) : subPath) : "";
            String url = String.format("%s/delete/%s/%s", this.extractCdsBaseUrl(config, true), section, subPathFixed);

            String result = this.executeDeleteCall(url, config, false);
            System.out.println("*********************************");
            System.out.println(result);
            System.out.println("*********************************");
            return true;
        } catch (Exception e) {
            logger.error("Error deleting file", e);
            throw new EntException("Error deleting file", e);
        }
    }
    
    private String executeDeleteCall(String url, TenantConfig config, boolean force) {
        try {
            HttpHeaders headers = this.getBaseHeader(null, config, force);
            HttpEntity<String> entity = new HttpEntity<>(headers);
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<String> responseEntity = restTemplate.exchange(url, HttpMethod.DELETE, entity, String.class);
            return responseEntity.getBody();
        } catch (HttpClientErrorException e) {
            if (!force && e.getStatusCode().equals(HttpStatus.UNAUTHORIZED)) {
                return this.executeDeleteCall(url, config, true);
            } else {
                throw new EntRuntimeException("Invalid DELETE, response status " + e.getStatusCode() + " - url " + url);
            }
        }
    }

    @Override
    public void createDirectory(String subPath, boolean isProtectedResource) throws EntException {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public void deleteDirectory(String subPath, boolean isProtectedResource) throws EntException {
        //throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public InputStream getStream(String subPath, boolean isProtectedResource) throws EntException {
        String url = null;
        try {
            byte[] bytes = null;
            TenantConfig config = this.getTenantConfig();
            String section = this.getSection(isProtectedResource);
            String baseUrl = (null != config) ? 
                ((isProtectedResource) ? config.getProperty(CDS_PRIVATE_URL_TENANT_PARAM) : config.getProperty(CDS_PUBLIC_URL_TENANT_PARAM)) :
                ((isProtectedResource) ? this.getCdpPrivateUrl() : this.getCdsPublicUrl());
            baseUrl = (baseUrl.endsWith(URL_SEP)) ? baseUrl.substring(0, baseUrl.length()-2) : baseUrl;
            String subPathFixed = (!StringUtils.isBlank(subPath)) ? (subPath.trim().startsWith(URL_SEP) ? subPath.trim().substring(1) : subPath) : "";
            url = baseUrl + URL_SEP + section + URL_SEP + subPathFixed;
            if (isProtectedResource) {
                bytes = this.executeGetCall(url, null, config, false, byte[].class);
            } else {
                RestTemplate restTemplate = new RestTemplate();
                bytes = restTemplate.getForObject(url, byte[].class);
            }
            return new ByteArrayInputStream(bytes);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode().equals(HttpStatus.NOT_FOUND)) {
                logger.info("File Not found - uri {}", url);
                return null;
            }  
            logger.error("Error extracting file", e);
            throw new EntException("Error extracting file", e);
        } catch (Exception e) {
            logger.error("Error extracting file", e);
            throw new EntException("Error extracting file", e);
        }
    }

    @Override
    public String getResourceUrl(String subPath, boolean isProtectedResource) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public boolean exists(String subPath, boolean isProtectedResource) throws EntException {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public BasicFileAttributeView getAttributes(String subPath, boolean isProtectedResource) throws EntException {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public String[] list(String subPath, boolean isProtectedResource) throws EntException {
        return this.listString(subPath, isProtectedResource, null);
    }

    @Override
    public String[] listDirectory(String subPath, boolean isProtectedResource) throws EntException {
        return this.listString(subPath, isProtectedResource, false);
    }

    @Override
    public String[] listFile(String subPath, boolean isProtectedResource) throws EntException {
        return this.listString(subPath, isProtectedResource, true);
    }
    
    protected String[] listString(String subPath, boolean isProtectedResource, Boolean file) throws EntException {
        BasicFileAttributeView[] list = this.listAttributes(subPath, isProtectedResource, file);
        List<String> names = Arrays.asList(list).stream()
                .map(bfa -> bfa.getName()).collect(Collectors.toList());
        return names.stream().toArray(String[]::new);
    }
    
    @Override
    public BasicFileAttributeView[] listAttributes(String subPath, boolean isProtectedResource) throws EntException {
        return this.listAttributes(subPath, isProtectedResource, null);
    }
    
    @Override
    public BasicFileAttributeView[] listDirectoryAttributes(String subPath, boolean isProtectedResource) throws EntException {
        return this.listAttributes(subPath, isProtectedResource, false);
    }

    @Override
    public BasicFileAttributeView[] listFileAttributes(String subPath, boolean isProtectedResource) throws EntException {
        return this.listAttributes(subPath, isProtectedResource, true);
    }
    
    protected BasicFileAttributeView[] listAttributes(String subPath, boolean isProtectedResource, Boolean file) throws EntException {
        try {
            TenantConfig config = this.getTenantConfig();
            String subPathFixed = (!StringUtils.isBlank(subPath)) ? (subPath.trim().startsWith(URL_SEP) ? subPath.trim().substring(1) : subPath) : "";
            String section = this.getSection(isProtectedResource);
            String url = String.format("%s/list/%s/%s", this.extractCdsBaseUrl(config, true), section, subPathFixed);
            String responseString = this.executeGetCall(url, Arrays.asList(MediaType.APPLICATION_JSON), config, false, String.class);
            CdsFileAttributeView[] cdsFileList = this.objectMapper.readValue(responseString, new TypeReference<CdsFileAttributeView[]>() {});
            List<BasicFileAttributeView> list = Arrays.asList(cdsFileList).stream()
                    .filter(csdf -> (null != file) ? ((file) ? !csdf.getDirectory() : csdf.getDirectory()) : true)
                    .map(csdf -> {
                BasicFileAttributeView bfa = new BasicFileAttributeView();
                bfa.setName(csdf.getName());
                bfa.setDirectory(csdf.getDirectory());
                bfa.setSize(csdf.getSize());
                return bfa;
            }).collect(Collectors.toList());
            if (list.size() == 1 && list.get(0).getName().equalsIgnoreCase(WRONG_PATH_NAME)) {
                logger.info("Invalid path {} - protected {}", subPath, isProtectedResource);
                return new BasicFileAttributeView[0];
            }
            Collections.sort(list);
            return list.stream().toArray(BasicFileAttributeView[]::new);
        } catch (Exception e) {
            logger.error("Error on list attributes", e);
            throw new EntException("Error on list attributes", e);
        }
    }
    
    private <T> T executeGetCall(String url, List<MediaType> acceptableMediaTypes, TenantConfig config, boolean force, Class<T> expectedType) {
        try {
            HttpHeaders headers = this.getBaseHeader(acceptableMediaTypes, config, force);
            HttpEntity<String> entity = new HttpEntity<>(headers);
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<T> responseEntity = restTemplate.exchange(url, HttpMethod.GET, entity, expectedType);
            return responseEntity.getBody();
        } catch (HttpClientErrorException e) {
            if (!force && e.getStatusCode().equals(HttpStatus.UNAUTHORIZED)) {
                return this.executeGetCall(url, acceptableMediaTypes, config, true, expectedType);
            } else {
                throw new EntRuntimeException("Invalid GET, response status " + e.getStatusCode() + " - url " + url);
            }
        }
    }
    
    private HttpHeaders getBaseHeader(List<MediaType> acceptableMediaTypes, TenantConfig config, boolean forceToken) {
        String token = this.extractToken(config, forceToken);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token);
        if (null != acceptableMediaTypes) {
            headers.setAccept(acceptableMediaTypes);
        }
        return headers;
    }

    @Override
    public String readFile(String subPath, boolean isProtectedResource) throws EntException {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public void editFile(String subPath, boolean isProtectedResource, InputStream is) throws EntException {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public String createFullPath(String subPath, boolean isProtectedResource) throws EntException {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public <T> T withValidResourcePath(String resourceRelativePath, boolean isProtectedResource, BiFunction<String, String, T> bip) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }
    
    private TenantConfig getTenantConfig() {
        String tenantCode = (String) EntThreadLocal.get(ITenantManager.THREAD_LOCAL_TENANT_CODE);
        TenantConfig config = null;
        if (!StringUtils.isBlank(tenantCode)) {
            config = this.getTenantManager().getConfig(tenantCode);
        }
        return config;
    }
    
    private String extractCdsBaseUrl(TenantConfig config, boolean privatePath) {
        String baseUrl = (null != config) ? 
                ((privatePath) ? config.getProperty(CDS_PRIVATE_URL_TENANT_PARAM) : config.getProperty(CDS_PUBLIC_URL_TENANT_PARAM)) :
                ((privatePath) ? this.getCdpPrivateUrl() : this.getCdsPublicUrl());
        String path = (null != config) ? config.getProperty(CDS_PATH_TENANT_PARAM) : this.getCdsPath();
        baseUrl = (baseUrl.endsWith(URL_SEP)) ? baseUrl.substring(0, baseUrl.length()-2) : baseUrl;
        path = (path.startsWith(URL_SEP)) ? path : URL_SEP + path;
        String cdsBaseUrl = baseUrl + path;
        return (cdsBaseUrl.endsWith(URL_SEP)) ? cdsBaseUrl.substring(0, cdsBaseUrl.length() - 2) : cdsBaseUrl;
    }
    
    private String getSection(boolean isProtectedResource) {
        return (isProtectedResource) ? SECTION_PRIVATE : SECTION_PUBLIC;
    } 
    
    private String extractToken(TenantConfig config, boolean force) {
        String token = null;
        if (null != config) {
            if (!force) {
                token = this.tenantsToken.get(config.getTenantCode());
            }
            if (null == token) {
                token = this.extractToken(config.getKcAuthUrl(), config.getKcRealm(), config.getKcClientId(), config.getKcClientSecret());
                this.tenantsToken.put(config.getTenantCode(), token);
            }
        } else {
            if (!force) {
                token = this.tenantsToken.get(PRIMARY_CODE);
            }
            if (null == token) {
                token = this.extractToken(this.getKcAuthUrl(), this.getKcRealm(), this.getKcClientId(), this.getKcClientSecret());
                this.tenantsToken.put(PRIMARY_CODE, token);
            }
        }
        return token;
    }
    
    private String extractToken(String kcUrl, String kcRealm, String clientId, String clientSecret) {
        RestTemplate restTemplate = new RestTemplate();
        final HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();
        CloseableHttpClient httpClient = HttpClientBuilder.create()
                .setRedirectStrategy(new LaxRedirectStrategy()).build();
        factory.setHttpClient(httpClient);
        restTemplate.setRequestFactory(factory);
        String encodedClientData = Base64Utils.encodeToString((clientId + ":" + clientSecret).getBytes());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + encodedClientData);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add(OAuth2Utils.GRANT_TYPE, "client_credentials");
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
        String url = String.format("%s/realms/%s/protocol/openid-connect/token", kcUrl, kcRealm);
        ResponseEntity<Map> responseEntity = restTemplate.postForEntity(url, request, Map.class);
        if (!responseEntity.getStatusCode().equals(HttpStatus.OK)) {
            throw new EntRuntimeException("Token api - invalid response status " + responseEntity.getStatusCode() + " - KC url " + kcUrl + " - realm " + kcRealm + " - client " + clientId);
        }
        return responseEntity.getBody().get(OAuth2AccessToken.ACCESS_TOKEN).toString();
    }

    public String getCdsPublicUrl() {
        return cdsPublicUrl;
    }
    public void setCdsPublicUrl(String cdsPublicUrl) {
        this.cdsPublicUrl = cdsPublicUrl;
    }

    public String getCdpPrivateUrl() {
        return cdpPrivateUrl;
    }
    public void setCdpPrivateUrl(String cdpPrivateUrl) {
        this.cdpPrivateUrl = cdpPrivateUrl;
    }

    public String getCdsPath() {
        return cdsPath;
    }
    public void setCdsPath(String cdsPath) {
        this.cdsPath = cdsPath;
    }

    public String getKcAuthUrl() {
        return kcAuthUrl;
    }
    public void setKcAuthUrl(String kcAuthUrl) {
        this.kcAuthUrl = kcAuthUrl;
    }

    public String getKcRealm() {
        return kcRealm;
    }
    public void setKcRealm(String kcRealm) {
        this.kcRealm = kcRealm;
    }

    public String getKcClientId() {
        return kcClientId;
    }
    public void setKcClientId(String kcClientId) {
        this.kcClientId = kcClientId;
    }

    public String getKcClientSecret() {
        return kcClientSecret;
    }
    public void setKcClientSecret(String kcClientSecret) {
        this.kcClientSecret = kcClientSecret;
    }

    protected ITenantManager getTenantManager() {
        return tenantManager;
    }
    @Autowired
    public void setTenantManager(ITenantManager tenantManager) {
        this.tenantManager = tenantManager;
    }
    
}
