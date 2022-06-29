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
import com.agiletec.aps.util.FileTextReader;
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
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.entando.entando.aps.system.services.storage.BasicFileAttributeView;
import org.entando.entando.aps.system.services.storage.IStorageManager;
import org.entando.entando.aps.system.services.storage.LocalStorageManager;
import org.entando.entando.aps.system.services.storage.StorageManagerUtil;
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
public class CdsStorageManager extends LocalStorageManager implements IStorageManager {
    
    private static final EntLogger logger = EntLogFactory.getSanitizedLogger(CdsStorageManager.class);
    
    private static final String PRIMARY_CODE = "PRIMARY_CODE";
    
    private static final String CDS_PUBLIC_URL_TENANT_PARAM = "cdsPublicUrl";
    private static final String CDS_PRIVATE_URL_TENANT_PARAM = "cdsPrivateUrl";
    private static final String CDS_PATH_TENANT_PARAM = "cdsPath";
    
    private static final String URL_SEP = "/";
    
    private static final String SECTION_PUBLIC = "public";
    private static final String SECTION_PRIVATE = "protected";
    
    private boolean enabled;        
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
        if (!this.isEnabled()) {
            return super.getBaseResourceUrl(isProtected);
        }
        TenantConfig config = this.getTenantConfig();
        return this.getCheckedBaseUrl(config, false) + URL_SEP + SECTION_PUBLIC + URL_SEP;
    }
    
    @Override
    public void createDirectory(String subPath, boolean isProtectedResource) {
        if (!this.isEnabled()) {
            super.createDirectory(subPath, isProtectedResource);
            return;
        }
        this.create(subPath, isProtectedResource, null);
    }
    
    @Override
    public void saveFile(String subPath, boolean isProtectedResource, InputStream is) throws EntException, IOException {
        if (!this.isEnabled()) {
            super.saveFile(subPath, isProtectedResource, is);
            return;
        }
        this.create(subPath, isProtectedResource, is);
    }
    
    protected void create(String subPath, boolean isProtectedResource, InputStream is) {
        try {
            TenantConfig config = this.getTenantConfig();
            this.validateAndReturnResourcePath(config, subPath, isProtectedResource);
            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            if (null != is) {
                //added file
                String filename = subPath;
                String path = "";
                int sepIndex = subPath.lastIndexOf(URL_SEP);
                if (sepIndex >= 0) {
                    filename = subPath.substring(sepIndex + 1);
                    path = subPath.substring(0, sepIndex);
                }
                InputStreamResource resource = new InputStreamResource(is);
                body.add("path", path);
                body.add("protected", isProtectedResource);
                body.add("filename", filename);
                body.add("file", resource);
            } else {
                body.add("path", subPath);
                body.add("protected", isProtectedResource);
            }
            
            String url = String.format("%s/upload/", this.extractInternalCdsBaseUrl(config, true));
            String result = this.executePostCall(url, body, config, false);
            ObjectMapper mapper = new ObjectMapper();
            CdsCreateResponse[] response = mapper.readValue(result, new TypeReference<CdsCreateResponse[]>(){});
            if (!"OK".equalsIgnoreCase(response[0].getStatus())) {
                throw new EntRuntimeException("Invalid status - Response " + result);
            }
        } catch (EntRuntimeException ert) {
            throw ert;
        } catch (Exception e) {
            logger.error("Error saving file/directory", e);
            throw new EntRuntimeException("Error saving file/directory", e);
        }
    }
    
    /*
    public Resource getTestFile() throws IOException {
        return new FileSystemResource(new File("/home/eu/Desktop/TestFile.txt"));
    }
    */
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
    public boolean deleteFile(String subPath, boolean isProtectedResource) {
        if (!this.isEnabled()) {
            return super.deleteFile(subPath, isProtectedResource);
        }
        try {
            TenantConfig config = this.getTenantConfig();
            this.validateAndReturnResourcePath(config, subPath, isProtectedResource);
            String section = this.getInternalSection(isProtectedResource);
            String subPathFixed = (!StringUtils.isBlank(subPath)) ? (subPath.trim().startsWith(URL_SEP) ? subPath.trim().substring(1) : subPath) : "";
            String url = String.format("%s/delete/%s/%s", this.extractInternalCdsBaseUrl(config, true), section, subPathFixed);
            String result = this.executeDeleteCall(url, config, false);
            Map<String, String> map = new ObjectMapper().readValue(result, new TypeReference<HashMap<String, String>>(){});
            return ("OK".equalsIgnoreCase(map.get("status")));
        } catch (EntRuntimeException ert) {
            throw ert;
        } catch (Exception e) {
            logger.error("Error deleting file", e);
            throw new EntRuntimeException("Error deleting file", e);
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
    public void deleteDirectory(String subPath, boolean isProtectedResource) throws EntException {
        if (!this.isEnabled()) {
            super.deleteDirectory(subPath, isProtectedResource);
            return;
        }
        this.deleteFile(subPath, isProtectedResource); //same behavior
    }

    @Override
    public InputStream getStream(String subPath, boolean isProtectedResource) throws EntException {
        if (!this.isEnabled()) {
            return super.getStream(subPath, isProtectedResource);
        }
        String url = null;
        try {
            TenantConfig config = this.getTenantConfig();
            this.validateAndReturnResourcePath(config, subPath, isProtectedResource);
            String section = this.getInternalSection(isProtectedResource);
            String baseUrl = this.getCheckedBaseUrl(config, isProtectedResource);
            String subPathFixed = (!StringUtils.isBlank(subPath)) ? (subPath.trim().startsWith(URL_SEP) ? subPath.trim().substring(1) : subPath) : "";
            url = baseUrl + URL_SEP + section + URL_SEP + subPathFixed;
            byte[] bytes = null;
            if (isProtectedResource) {
                bytes = this.executeGetCall(url, null, config, false, byte[].class);
            } else {
                RestTemplate restTemplate = new RestTemplate();
                bytes = restTemplate.getForObject(url, byte[].class);
            }
            return new ByteArrayInputStream(bytes);
        } catch (EntRuntimeException ert) {
            throw ert;
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
        try {
            if (this.isEnabled() && !isProtectedResource) {
                TenantConfig config = this.getTenantConfig();
                return this.validateAndReturnResourcePath(config, subPath, isProtectedResource);
            }
            return super.getResourceUrl(subPath, isProtectedResource); // protected resources are serverd everytime from de-app
        } catch (Exception e) {
            logger.error("Error extracting resource url", e);
            throw new EntRuntimeException("Error extracting resource url", e);
        }
    }

    @Override
    public boolean exists(String subPath, boolean isProtectedResource) {
        if (!this.isEnabled()) {
            return super.exists(subPath, isProtectedResource);
        }
        String[] sections = this.extractSections(subPath);
        String[] filenames = this.list(sections[0], isProtectedResource);
        return (null != filenames && Arrays.asList(filenames).contains(sections[1]));
    }

    @Override
    public BasicFileAttributeView getAttributes(String subPath, boolean isProtectedResource) {
        if (!this.isEnabled()) {
            return super.getAttributes(subPath, isProtectedResource);
        }
        String[] sections = this.extractSections(subPath);
        BasicFileAttributeView[] attributs = this.listAttributes(sections[0], isProtectedResource);
        if (null == attributs) {
            return null;
        }
        for (int i = 0; i < attributs.length; i++) {
            BasicFileAttributeView attr = attributs[i];
            if (attr.getName().equals(sections[1])) {
                return attr;
            }
        }
        return null;
    }
    
    private String[] extractSections(String subPath) {
        String path = "";
        String filename = subPath;
        int sepIndex = subPath.lastIndexOf(URL_SEP);
        if (sepIndex >= 0) {
            path = subPath.substring(0, sepIndex);
            filename = subPath.substring(sepIndex + 1);
        }
        return new String[]{path, filename};
    }

    @Override
    public String[] list(String subPath, boolean isProtectedResource) {
        if (!this.isEnabled()) {
            return super.list(subPath, isProtectedResource);
        }
        return this.listString(subPath, isProtectedResource, null);
    }

    @Override
    public String[] listDirectory(String subPath, boolean isProtectedResource) {
        if (!this.isEnabled()) {
            return super.listDirectory(subPath, isProtectedResource);
        }
        return this.listString(subPath, isProtectedResource, false);
    }

    @Override
    public String[] listFile(String subPath, boolean isProtectedResource) {
        if (!this.isEnabled()) {
            return super.listFile(subPath, isProtectedResource);
        }
        return this.listString(subPath, isProtectedResource, true);
    }
    
    protected String[] listString(String subPath, boolean isProtectedResource, Boolean file) {
        BasicFileAttributeView[] list = this.listAttributes(subPath, isProtectedResource, file);
        List<String> names = Arrays.asList(list).stream()
                .map(bfa -> bfa.getName()).collect(Collectors.toList());
        return names.stream().toArray(String[]::new);
    }
    
    @Override
    public BasicFileAttributeView[] listAttributes(String subPath, boolean isProtectedResource) {
        if (!this.isEnabled()) {
            return super.listAttributes(subPath, isProtectedResource);
        }
        return this.listAttributes(subPath, isProtectedResource, null);
    }
    
    @Override
    public BasicFileAttributeView[] listDirectoryAttributes(String subPath, boolean isProtectedResource) {
        if (!this.isEnabled()) {
            return super.listDirectoryAttributes(subPath, isProtectedResource);
        }
        return this.listAttributes(subPath, isProtectedResource, false);
    }

    @Override
    public BasicFileAttributeView[] listFileAttributes(String subPath, boolean isProtectedResource) {
        if (!this.isEnabled()) {
            return super.listFileAttributes(subPath, isProtectedResource);
        }
        return this.listAttributes(subPath, isProtectedResource, true);
    }
    
    protected BasicFileAttributeView[] listAttributes(String subPath, boolean isProtectedResource, Boolean file) {
        try {
            TenantConfig config = this.getTenantConfig();
            this.validateAndReturnResourcePath(config, subPath, isProtectedResource);
            String subPathFixed = (!StringUtils.isBlank(subPath)) ? (subPath.trim().startsWith(URL_SEP) ? subPath.trim().substring(1) : subPath) : "";
            String section = this.getInternalSection(isProtectedResource);
            String url = String.format("%s/list/%s/%s", this.extractInternalCdsBaseUrl(config, true), section, subPathFixed);
            String responseString = this.executeGetCall(url, Arrays.asList(MediaType.APPLICATION_JSON), config, false, String.class);
            if (null == responseString) {
                return new BasicFileAttributeView[0];
            }
            CdsFileAttributeView[] cdsFileList = this.objectMapper.readValue(responseString, new TypeReference<CdsFileAttributeView[]>() {});
            List<BasicFileAttributeView> list = Arrays.asList(cdsFileList).stream()
                    .filter(csdf -> (null != file) ? ((file) ? !csdf.getDirectory() : csdf.getDirectory()) : true)
                    .map(csdf -> {
                BasicFileAttributeView bfa = new BasicFileAttributeView();
                bfa.setName(csdf.getName());
                bfa.setDirectory(csdf.getDirectory());
                bfa.setLastModifiedTime(csdf.getDate());
                bfa.setSize(csdf.getSize());
                return bfa;
            }).collect(Collectors.toList());
            Collections.sort(list);
            return list.stream().toArray(BasicFileAttributeView[]::new);
        } catch (EntRuntimeException ert) {
            throw ert;
        } catch (Exception e) {
            logger.error("Error on list attributes", e);
            throw new EntRuntimeException("Error on list attributes", e);
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
            if (e.getStatusCode().equals(HttpStatus.NOT_FOUND)) {
                logger.info("File Not found - uri {}", url);
                return null;
            }
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
        if (!this.isEnabled()) {
            return super.readFile(subPath, isProtectedResource);
        }
        try {
            InputStream stream = this.getStream(subPath, isProtectedResource);
            return FileTextReader.getText(stream);
        } catch (EntRuntimeException ert) {
            throw ert;
        } catch (IOException ex) {
            logger.error("Error extracting text", ex);
            throw new EntException("Error extracting text", ex);
        }
    }

    @Override
    public void editFile(String subPath, boolean isProtectedResource, InputStream is) throws EntException {
        if (!this.isEnabled()) {
            super.editFile(subPath, isProtectedResource, is);
            return;
        }
        try {
            this.saveFile(subPath, isProtectedResource, is);
        } catch (EntRuntimeException ert) {
            throw ert;
        } catch (IOException ex) {
            logger.error("Error editing text", ex);
            throw new EntException("Error editing text", ex);
        }
    }

    @Override
    public String createFullPath(String subPath, boolean isProtectedResource) {
        if (!this.isEnabled()) {
            return super.createFullPath(subPath, isProtectedResource);
        }
        TenantConfig config = this.getTenantConfig();
        return this.validateAndReturnResourcePath(config, subPath, isProtectedResource);
    }
    
    private TenantConfig getTenantConfig() {
        String tenantCode = (String) EntThreadLocal.get(ITenantManager.THREAD_LOCAL_TENANT_CODE);
        TenantConfig config = null;
        if (!StringUtils.isBlank(tenantCode)) {
            config = this.getTenantManager().getConfig(tenantCode);
        }
        return config;
    }
    
    private String getInternalSection(boolean isProtectedResource) {
        return (isProtectedResource) ? SECTION_PRIVATE : SECTION_PUBLIC;
    } 
    
    private String extractToken(TenantConfig config, boolean force) {
        String token = null;
        if (null != config) {
            if (!force) {
                token = this.tenantsToken.get(config.getTenantCode());
            }
            if (StringUtils.isBlank(token)) {
                token = this.extractToken(config.getKcAuthUrl(), config.getKcRealm(), config.getKcClientId(), config.getKcClientSecret());
                this.tenantsToken.put(config.getTenantCode(), token);
            }
        } else {
            if (!force) {
                token = this.tenantsToken.get(PRIMARY_CODE);
            }
            if (StringUtils.isBlank(token)) {
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
    
    private String extractInternalCdsBaseUrl(TenantConfig config, boolean privateUrl) {
        String baseUrl = this.getCheckedBaseUrl(config, privateUrl);
        String path = (null != config) ? config.getProperty(CDS_PATH_TENANT_PARAM) : this.getCdsPath();
        path = (path.startsWith(URL_SEP)) ? path : URL_SEP + path;
        String cdsBaseUrl = baseUrl + path;
        return (cdsBaseUrl.endsWith(URL_SEP)) ? cdsBaseUrl.substring(0, cdsBaseUrl.length() - 2) : cdsBaseUrl;
    }
    
    protected String validateAndReturnResourcePath(TenantConfig config, String resourceRelativePath, boolean privateUrl) {
        try {
            String baseUrl = this.getCheckedBaseUrl(config, privateUrl) + URL_SEP + this.getInternalSection(privateUrl);
            String fullPath = this.createPath(baseUrl, resourceRelativePath);
            if (!StorageManagerUtil.doesPathContainsPath(baseUrl, fullPath, true)) {
                throw mkPathValidationErr(baseUrl, fullPath);
            }
            return fullPath;
        } catch (EntRuntimeException ert) {
            throw ert;
        } catch (Exception e) {
            logger.error("Error validating path", e);
            throw new EntRuntimeException("Error validating path", e);
        }
    }
    
    private String getCheckedBaseUrl(TenantConfig config, boolean privateUrl) {
        String baseUrl = (null != config)
                ? ((privateUrl) ? config.getProperty(CDS_PRIVATE_URL_TENANT_PARAM) : config.getProperty(CDS_PUBLIC_URL_TENANT_PARAM))
                : ((privateUrl) ? this.getCdpPrivateUrl() : this.getCdsPublicUrl());
        baseUrl = (baseUrl.endsWith(URL_SEP)) ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        return baseUrl;
    }

	private String createPath(String basePath, String subPath) {
		subPath = (null == subPath) ? "" : subPath;
        basePath = (basePath.endsWith(URL_SEP)) ? basePath.substring(0, basePath.length() - URL_SEP.length() - 1) : basePath;
        subPath = (subPath.startsWith(URL_SEP)) ? subPath.substring(URL_SEP.length()) : subPath;
        return (StringUtils.isBlank(subPath)) ? basePath : basePath + URL_SEP + subPath;
	}

	private EntRuntimeException mkPathValidationErr(String diskRoot, String fullPath) {
		return new EntRuntimeException(
				String.format("Path validation failed: \"%s\" not in \"%s\"", fullPath, diskRoot)
		);
	}

    protected boolean isEnabled() {
        return enabled;
    }
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
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
