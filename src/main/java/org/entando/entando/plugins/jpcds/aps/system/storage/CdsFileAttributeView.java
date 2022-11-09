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

import java.io.Serializable;
import java.util.Date;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;

/**
 * @author E.Santoboni
 */
public class CdsFileAttributeView implements Serializable {
    
    public static final String LONG_TIME_PARAM_NAME = "secs_since_epoch";
    
    private String name;
	private Map<String,String> last_modified_time;
	private Long size;
	private Boolean directory;
	private String path;
	private Boolean protected_folder;

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }

    public Map<String, String> getLast_modified_time() {
        return last_modified_time;
    }

    public void setLast_modified_time(Map<String, String> last_modified_time) {
        this.last_modified_time = last_modified_time;
    }
    
    public Date getDate() {
        String timeString = this.getLast_modified_time().get(LONG_TIME_PARAM_NAME);
        if (!StringUtils.isBlank(timeString)) {
            return new Date(Long.valueOf(timeString)*1000);
        }
        return null;
    }

    public Long getSize() {
        return size;
    }
    public void setSize(Long size) {
        this.size = size;
    }

    public Boolean getDirectory() {
        return directory;
    }
    public void setDirectory(Boolean directory) {
        this.directory = directory;
    }

    public String getPath() {
        return path;
    }
    public void setPath(String path) {
        this.path = path;
    }

    public Boolean getProtected_folder() {
        return protected_folder;
    }
    public void setProtected_folder(Boolean protectedFolder) {
        this.protected_folder = protectedFolder;
    }
    
}
