/*
 * Copyright 2015-Present Entando Inc. (http://www.entando.com) All rights reserved.
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.hamcrest.MatcherAssert.assertThat;

import com.agiletec.aps.BaseTestCase;
import com.agiletec.aps.system.EntThreadLocal;
import com.agiletec.aps.util.FileTextReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import org.apache.commons.io.IOUtils;
import org.entando.entando.aps.system.services.storage.BasicFileAttributeView;
import org.entando.entando.aps.system.services.storage.IStorageManager;
import org.entando.entando.aps.system.services.tenant.ITenantManager;
import org.entando.entando.ent.exception.EntException;
import org.entando.entando.ent.exception.EntRuntimeException;
import org.entando.entando.ent.util.EntLogging.EntLogFactory;
import org.entando.entando.ent.util.EntLogging.EntLogger;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * @author S.Loru - E.Santoboni
 */
class CdsStorageManagerIntegrationTest extends BaseTestCase {

    private static final EntLogger logger = EntLogFactory.getSanitizedLogger(CdsStorageManagerIntegrationTest.class);
    
    @Test
    void testInitialize() {
        Assertions.assertNotNull(cdsStorageManager);
    }
/*
    @Test
    void testStorageFileList() throws Throwable {
        String[] filenames = localStorageManager.listFile("", false);
        assertEquals(1, filenames.length);
        assertEquals("entando_logo.jpg", filenames[0]);
        filenames = localStorageManager.listFile("conf" + File.separator, false);
        assertEquals(3, filenames.length);
        for (int i = 0; i < filenames.length; i++) {
            String filename = filenames[i];
            assertTrue(filename.equals("contextTestParams.properties") || filename.equals("systemParams.properties")
                    || filename.equals("security.properties"));
        }
    }
    
    @Test
    void testStorageDirectoryList() throws Throwable {
        String[] directoryNames = localStorageManager.listDirectory("", false);
        assertTrue(directoryNames.length >= 1);
        List<String> list = Arrays.asList(directoryNames);
        assertTrue(list.contains("conf"));

        directoryNames = localStorageManager.listDirectory("conf" + File.separator, false);
        assertEquals(0, directoryNames.length);
    }
*/
    
    @Test
    void testListAttributes() throws Throwable {
        BasicFileAttributeView[] fileAttributes = cdsStorageManager.listAttributes("", false);
        boolean containsCms = false;
        boolean prevDirectory = true;
        String prevName = null;
        for (int i = 0; i < fileAttributes.length; i++) {
            BasicFileAttributeView bfav = fileAttributes[i];
            if (!prevDirectory && bfav.isDirectory()) {
                fail();
            }
            if (bfav.isDirectory() && bfav.getName().equals("cms")) {
                containsCms = true;
            }
            if ((bfav.isDirectory() == prevDirectory) && null != prevName) {
                assertTrue(bfav.getName().compareTo(prevName) > 0);
            }
            prevName = bfav.getName();
            prevDirectory = bfav.isDirectory();
        }
        assertTrue(containsCms);
    }
    
    @Test
    void testListAttributes_2() throws Throwable {
        this.executeTestListAttributes_2();
        EntThreadLocal.set(ITenantManager.THREAD_LOCAL_TENANT_CODE, "tenant");
        this.executeTestListAttributes_2();
        EntThreadLocal.remove(ITenantManager.THREAD_LOCAL_TENANT_CODE);
    }
    
    void executeTestListAttributes_2() throws Throwable {
        BasicFileAttributeView[] fileAttributes = cdsStorageManager.listAttributes("cms" + File.separator, false);
        assertEquals(2, fileAttributes.length);
        int dirCounter = 0;
        int fileCounter = 0;
        for (int i = 0; i < fileAttributes.length; i++) {
            BasicFileAttributeView bfav = fileAttributes[i];
            if (bfav.isDirectory()) {
                dirCounter++;
            } else {
                fileCounter++;
            }
        }
        assertEquals(2, dirCounter);
        assertEquals(0, fileCounter);
        
        fileAttributes = cdsStorageManager.listDirectoryAttributes("cms" + File.separator, false);
        assertEquals(2, fileAttributes.length);
        
        fileAttributes = cdsStorageManager.listFileAttributes("cms" + File.separator, false);
        assertEquals(0, fileAttributes.length);
        
        String[] names = cdsStorageManager.list("cms" + File.separator, false);
        assertEquals(2, names.length);
        
        names = cdsStorageManager.listDirectory("cms" + File.separator, false);
        assertEquals(2, names.length);
        
        names = cdsStorageManager.listFile("cms" + File.separator, false);
        assertEquals(0, names.length);
        
    }

    @Test
    void testListAttributes_3() throws Throwable {
        // Non existent directory
        BasicFileAttributeView[] fileAttributes =
                cdsStorageManager.listAttributes("non-existent" + File.separator, false);
        assertEquals(0, fileAttributes.length);

        // Non-directory directory
        fileAttributes =
                cdsStorageManager.listAttributes("conf/security.properties" + File.separator, false);
        assertEquals(0, fileAttributes.length);
    }
    
    @Test
    void testGetStream_ShouldBlockPathTraversal() throws Throwable {
        String testFilePath = "../testfolder/test.txt";
        try {
            cdsStorageManager.getStream(testFilePath, false);
        } catch (EntRuntimeException e) {
            assertThat(e.getMessage(), CoreMatchers.startsWith("Path validation failed"));
        } catch (Throwable t) {
            fail("Shouldn't reach this point");
        }
    }
    
    @Test
    void testSaveEditDeleteFile() throws Throwable {
        String testFilePath = "testfolder/test.txt";
        InputStream stream = cdsStorageManager.getStream(testFilePath, false);
        Assertions.assertNull(stream);
        try {
            String content = "Content of new text file";
            cdsStorageManager.saveFile(testFilePath, false, new ByteArrayInputStream(content.getBytes()));
            Assertions.assertTrue(cdsStorageManager.exists(testFilePath, false));
            stream = cdsStorageManager.getStream(testFilePath, false);
            Assertions.assertNotNull(stream);
            String extractedString = IOUtils.toString(stream, "UTF-8");
            stream.close();
            Assertions.assertEquals(content, extractedString);
            String newContent = "This is the new content of text file";
            cdsStorageManager.editFile(testFilePath, false, new ByteArrayInputStream(newContent.getBytes()));
            stream = cdsStorageManager.getStream(testFilePath, false);
            String extractedNewString = IOUtils.toString(stream, "UTF-8");
            stream.close();
            Assertions.assertEquals(newContent, extractedNewString);
            String readfileAfterWriteBackup = cdsStorageManager.readFile(testFilePath, false);
            Assertions.assertEquals(extractedNewString.trim(), readfileAfterWriteBackup.trim());
            boolean deleted = cdsStorageManager.deleteFile(testFilePath, false);
            assertTrue(deleted);
            Assertions.assertFalse(cdsStorageManager.exists(testFilePath, false));
            stream = cdsStorageManager.getStream(testFilePath, false);
            Assertions.assertNull(stream);
        } catch (Throwable t) {
            throw t;
        } finally {
            if (null != stream) {
                stream.close();
            }
            cdsStorageManager.deleteDirectory("testfolder/", false);
            InputStream streamBis = cdsStorageManager.getStream(testFilePath, false);
            Assertions.assertNull(streamBis);
        }
        // file not found case
        Assertions.assertFalse(cdsStorageManager.deleteFile("non-existent", false));
    }
    
    @Test
    void testSaveEditDeleteFile_2() throws Throwable {
        String testFilePath = "testfolder_2/architectureUploaded.txt";
        InputStream stream = null;
        try {
            stream = cdsStorageManager.getStream(testFilePath, false);
            Assertions.assertNull(stream);
            File file = new File("src/test/resources/document/architecture.txt");
            cdsStorageManager.saveFile(testFilePath, false, new FileInputStream(file));
            stream = cdsStorageManager.getStream(testFilePath, false);
            Assertions.assertNotNull(stream);
            
            String originalText = FileTextReader.getText("src/test/resources/document/architecture.txt");
            String extractedText = FileTextReader.getText(stream);
            Assertions.assertEquals(originalText, extractedText);
            
            boolean deleted = cdsStorageManager.deleteFile(testFilePath, false);
            assertTrue(deleted);
            stream = cdsStorageManager.getStream(testFilePath, false);
            Assertions.assertNull(stream);
        } catch (Throwable t) {
            throw t;
        } finally {
            if (null != stream) {
                stream.close();
            }
            cdsStorageManager.deleteDirectory("testfolder_2/", false);
            InputStream streamBis = cdsStorageManager.getStream(testFilePath, false);
            Assertions.assertNull(streamBis);
        }
        // file not found case
        Assertions.assertFalse(cdsStorageManager.deleteFile("non-existent", false));
    }
    
    @Test
    void testCreateDeleteFile_ShouldBlockPathTraversals() throws Throwable {
        String testFilePath = "../../testfolder/test.txt";
        String content = "Content of new text file";
        EntRuntimeException exc1 = Assertions.assertThrows(EntRuntimeException.class, () -> {
            this.cdsStorageManager.saveFile(testFilePath, false, new ByteArrayInputStream(content.getBytes()));
        });
        assertThat(exc1.getMessage(), CoreMatchers.startsWith("Path validation failed"));
        EntRuntimeException exc2 = Assertions.assertThrows(EntRuntimeException.class, () -> {
            this.cdsStorageManager.deleteFile(testFilePath, false);
        });
        assertThat(exc2.getMessage(), CoreMatchers.startsWith("Path validation failed"));
    }
    
    @Test
    void testCreateDeleteDir() throws EntException {
        String directoryName = "testfolder";
        String subDirectoryName = "subfolder";
        Assertions.assertFalse(this.cdsStorageManager.exists(directoryName, false));
        try {
            this.cdsStorageManager.createDirectory(directoryName + File.separator + subDirectoryName, false);
            assertTrue(this.cdsStorageManager.exists(directoryName, false));
            String[] listDirectory = this.cdsStorageManager.listDirectory(directoryName, false);
            assertEquals(1, listDirectory.length);
            listDirectory = this.cdsStorageManager.listDirectory(directoryName + File.separator + subDirectoryName, false);
            assertEquals(0, listDirectory.length);
        } finally {
            this.cdsStorageManager.deleteDirectory(directoryName, false);
            Assertions.assertFalse(this.cdsStorageManager.exists(directoryName, false));
        }
    }
    
    /*
    @Test
    void testCreateDeleteDir_ShouldHandleFailureCases() throws EntException {
        String baseFolder = "non-existent";
        String endingFolder = "dir-to-create";
        String fullPath = baseFolder + File.separator + endingFolder;
        Functions.FailableBiConsumer<String, Boolean, EntException> assertExists = (p, exp) ->
                assertEquals(exp, (Boolean) localStorageManager.exists(p, false));

        // Simple fail by duplication or not found
        try {
            localStorageManager.createDirectory(fullPath, false);
            assertExists.accept(fullPath, true);
            localStorageManager.createDirectory(fullPath, false);
            assertExists.accept(fullPath, true);
            localStorageManager.deleteDirectory(fullPath, false);
            assertExists.accept(fullPath, false);
        } finally {
            localStorageManager.deleteDirectory(baseFolder, false);
            assertFalse(localStorageManager.exists(baseFolder, false));
        }
    }

    @Test
    void testCreateDeleteDirectory_ShouldBlockPathTraversals() throws Throwable {
        EntRuntimeException exc1 = Assertions.assertThrows(EntRuntimeException.class, () -> {
            this.localStorageManager.createDirectory("/../../../dev/mydir", false);
        });
        assertThat(exc1.getMessage(), CoreMatchers.startsWith("Path validation failed"));

        EntRuntimeException exc2 = Assertions.assertThrows(EntRuntimeException.class, () -> {
            this.localStorageManager.deleteDirectory("/../../../dev/mydir", false);
        });
        assertThat(exc2.getMessage(), CoreMatchers.startsWith("Path validation failed"));
        this.localStorageManager.createDirectory("target/mydir", false);
        BasicFileAttributeView[] attributes = this.localStorageManager.listAttributes("target/mydir", false);
        assertNotNull(attributes);
        assertEquals(0, attributes.length);
        this.localStorageManager.deleteDirectory("target/mydir", false);
        this.localStorageManager.deleteDirectory("target", false);
    }
*/
    @BeforeEach
    private void init() throws Exception {
        try {
            cdsStorageManager = this.getApplicationContext().getBean(IStorageManager.class);
        } catch (Throwable t) {
            logger.error("error on init", t);
        }
    }

    private IStorageManager cdsStorageManager;

}
