/*
 * This file is part of pit - https://github.com/FlorianMichael/pit
 * Copyright (C) 2025 FlorianMichael/EnZaXD <florian.michael07@gmail.com> and contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.florianmichael.pit;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static de.florianmichael.pit.KeyUtils.deriveKey;

public final class FileUtils {

    private static final int SALT_LENGTH = 16;

    /**
     * Decrypts a specific entry from a Vault file.
     *
     * @param file      the Vault file containing the encrypted entry
     * @param entryName the name of the entry to decrypt
     * @param password  the password used for encryption
     * @return the decrypted content of the entry
     * @throws Exception if decryption fails or the entry is not found
     */
    public static byte[] decrypt(final File file, final String entryName, final String password) throws Exception {
        try (final FileInputStream fis = new FileInputStream(file);
             final ZipInputStream zis = new ZipInputStream(fis)) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (!entry.getName().equals(entryName)) {
                    continue;
                }

                final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                zis.transferTo(buffer);
                return decryptFile(buffer.toByteArray(), password);
            }
        }

        throw new FileNotFoundException("File not found in archive: " + entryName);
    }

    /**
     * Decrypts all entries in a Vault file and returns them as a map.
     *
     * @param file     the Vault file containing the encrypted entries
     * @param password the password used for encryption
     * @return a map where the keys are entry names and the values are the decrypted file contents
     * @throws Exception if decryption fails or an error occurs while reading the file
     */
    public static Map<String, byte[]> decrypt(final File file, final String password) throws Exception {
        final Map<String, byte[]> result = new HashMap<>();

        try (final FileInputStream fis = new FileInputStream(file);
             final ZipInputStream zis = new ZipInputStream(fis)) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }

                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                zis.transferTo(buffer);
                final byte[] fullContent = buffer.toByteArray();

                try {
                    result.put(entry.getName(), decryptFile(fullContent, password));
                } catch (Exception e) {
                    System.err.println("Failed to decrypt entry: " + entry.getName());
                    throw e;
                }
            }
        }

        return result;
    }

    /**
     * Encrypts multiple files into a Vault file.
     *
     * @param files    a map where the keys are file names and the values are the file contents as byte arrays
     * @param output   the output file where the encrypted content will be written
     * @param password the password used for encryption
     * @throws Exception if encryption fails or an error occurs while writing the file
     */
    public static void encrypt(final Map<String, byte[]> files, final File output, final String password) throws Exception {
        final Map<String, byte[]> allFiles = new HashMap<>();

        if (output.exists()) {
            try (final ZipFile zipFile = new ZipFile(output)) {
                zipFile.stream().forEach(entry -> {
                    try (InputStream is = zipFile.getInputStream(entry)) {
                        byte[] data = is.readAllBytes();
                        allFiles.put(entry.getName(), data);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                });
            }
        }

        allFiles.putAll(files);

        try (final FileOutputStream fos = new FileOutputStream(output);
             final ZipOutputStream zos = new ZipOutputStream(fos)) {

            for (Map.Entry<String, byte[]> entry : allFiles.entrySet()) {
                writeEncryptedZipEntry(zos, entry.getKey(), entry.getValue(), password);
            }
        }
    }

    public static void writeEncryptedZipEntry(final ZipOutputStream zos, final String name, final byte[] content, final String password) throws Exception {
        final byte[] salt = new byte[SALT_LENGTH];
        final byte[] iv = new byte[16];
        new SecureRandom().nextBytes(salt);
        new SecureRandom().nextBytes(iv);

        final SecretKey key = deriveKey(password, salt);
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        final byte[] encryptedData = cipher.doFinal(content);

        final ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(salt);
        stream.write(iv);
        stream.write(encryptedData);

        final ZipEntry zipEntry = new ZipEntry(name);
        zos.putNextEntry(zipEntry);
        zos.write(stream.toByteArray());
        zos.closeEntry();
    }

    // --------------------------

    /**
     * Encrypts all files in a folder into a Vault file.
     *
     * @param folderPath     the path to the folder containing files to encrypt
     * @param outputFilePath the path where the encrypted Vault file will be saved
     * @param password       the password used for encryption
     * @throws Exception if encryption fails or an error occurs while reading the folder
     */
    public static void encryptVault(final String folderPath, final String outputFilePath, final String password) throws Exception {
        final File folder = new File(folderPath);
        if (!folder.exists() || !folder.isDirectory()) {
            throw new IllegalArgumentException("Invalid folder: " + folderPath);
        }

        final Map<String, byte[]> files = new HashMap<>();
        loadFilesRecursively(folder, folder.getAbsolutePath(), files);
        encrypt(files, new File(outputFilePath), password);
    }

    /**
     * Decrypts a Vault file and extracts its contents to a specified folder.
     *
     * @param inputFilePath    the path to the Vault file to decrypt
     * @param outputFolderPath the path to the folder where decrypted files will be saved
     * @param password         the password used for decryption
     * @throws Exception if decryption fails or an error occurs while reading the Vault file
     */
    public static void decryptVault(final String inputFilePath, final String outputFolderPath, final String password) throws Exception {
        final Map<String, byte[]> files = decrypt(new File(inputFilePath), password);
        final Path outputBasePath = Paths.get(outputFolderPath).toAbsolutePath().normalize();

        for (final Map.Entry<String, byte[]> entry : files.entrySet()) {
            final Path outPath = outputBasePath.resolve(entry.getKey()).normalize();
            if (!outPath.startsWith(outputBasePath)) {
                throw new SecurityException("Invalid path: " + entry.getKey());
            }

            Files.createDirectories(outPath.getParent());
            Files.write(outPath, entry.getValue());
        }
    }

    private static void loadFilesRecursively(final File base, final String rootPath, final Map<String, byte[]> map) throws IOException {
        if (base.isDirectory()) {
            for (File file : base.listFiles()) {
                loadFilesRecursively(file, rootPath, map);
            }
        } else {
            final String relativePath = base.getAbsolutePath().substring(rootPath.length() + 1).replace("\\", "/");
            map.put(relativePath, Files.readAllBytes(base.toPath()));
        }
    }

    // --------------------------

    /**
     * Decrypts the bytes of a file into the actual file content.
     *
     * @param file     the encrypted file bytes
     * @param password the password used for encryption
     * @return the decrypted file content
     * @throws Exception if decryption fails
     */
    private static byte[] decryptFile(final byte[] file, final String password) throws Exception {
        if (file.length < SALT_LENGTH + 16) {
            throw new IllegalArgumentException("Encrypted entry is too short to be valid.");
        }

        final byte[] salt = new byte[SALT_LENGTH];
        final byte[] iv = new byte[16];
        System.arraycopy(file, 0, salt, 0, SALT_LENGTH);
        System.arraycopy(file, SALT_LENGTH, iv, 0, 16);

        final byte[] encryptedData = new byte[file.length - SALT_LENGTH - 16];
        System.arraycopy(file, SALT_LENGTH + 16, encryptedData, 0, encryptedData.length);

        final SecretKey key = deriveKey(password, salt);
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(encryptedData);
    }

}
