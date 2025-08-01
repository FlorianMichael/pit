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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public final class Pit {

    public static final int SALT_LENGTH = 16;

    public static void main(final String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Private Information Tracker (https://github.com/FlorianMichael/pit)");
            System.out.println();
            System.out.println("Save and load object files from a folder:");
            System.out.println("  Encrypt:   --encrypt (folder) (output file)");
            System.out.println("  Decrypt:   --decrypt (input file) (output folder)");
            System.out.println();
            System.out.println("Utilities to manage object files, specialized on accounts and passwords:");
            System.out.println("  View:      --view [input file] (file in archive)");
            System.out.println("  Add:       --add [encrypted file] [file to add]");
            System.out.println("  Remove:    --remove [encrypted file] [file to remove]");
            System.out.println("  Edit:      --edit [encrypted file] [file in archive] [new file]");
            System.out.println("  Write:     --write [encrypted file] [file name]");
            return;
        }

        final Console console = System.console();
        if (console == null) {
            System.err.println("Run from a terminal to securely input the password.");
            return;
        }

        final String password = new String(console.readPassword("Enter master password: "));
        switch (args[0].toLowerCase()) {
            case "-e":
            case "--encrypt":
                final String folder = args.length > 1 ? args[1] : "passwords";
                final String outputFile = args.length > 2 ? args[2] : "encrypted.zip";

                try {
                    encryptFolder(folder, outputFile, password);
                } catch (final Exception e) {
                    System.err.println("Encryption failed!");
                    throw e;
                }
                break;
            case "-d":
            case "--decrypt":
                final String inputFile = args.length > 1 ? args[1] : "encrypted.zip";
                final String outputFolder = args.length > 2 ? args[2] : "passwords";

                try {
                    decryptToFolder(inputFile, outputFolder, password);
                } catch (final Exception e) {
                    System.err.println("Decryption failed!");
                    System.err.println("Ensure the file is valid and the password is correct.");
                }
                break;

            case "-v":
            case "--view":
                if (args.length < 2) {
                    System.err.println("Usage: -v (encrypted file) [file inside archive]");
                    return;
                }

                final String encryptedFile = args[1];
                final String requestedFile = args.length > 2 ? args[2] : null;
                try {
                    if (requestedFile == null) {
                        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(encryptedFile))) {
                            ZipEntry entry;
                            System.out.println("Available files:");
                            while ((entry = zis.getNextEntry()) != null) {
                                if (!entry.isDirectory()) {
                                    System.out.println(" - " + entry.getName());
                                }
                            }
                        }
                        return;
                    }

                    final byte[] content = decryptSingleFileFromArchive(new File(encryptedFile), requestedFile, password);
                    System.out.println("Contents of " + requestedFile + ":\n");
                    System.out.println(new String(content, StandardCharsets.UTF_8));
                } catch (final Exception e) {
                    System.err.println("Failed to decrypt or read file!");
                    throw e;
                }
                break;
            case "--add":
                if (args.length < 3) {
                    System.err.println("Usage: --add [encrypted file] [file to add]");
                    return;
                }

                try {
                    final Map<String, byte[]> files = Pit.decryptToMemory(new File(args[1]), password);
                    final File fileToAdd = new File(args[2]);
                    files.put(fileToAdd.getName(), Files.readAllBytes(fileToAdd.toPath()));
                    Pit.encryptFromMemory(files, new File(args[1]), password);
                    System.out.println("File added: " + fileToAdd.getName());
                } catch (final Exception e) {
                    System.err.println("Failed to add file!");
                    throw e;
                }
                break;
            case "--remove":
                if (args.length < 3) {
                    System.err.println("Usage: --remove [encrypted file] [file to remove]");
                    return;
                }

                try {
                    final Map<String, byte[]> files = Pit.decryptToMemory(new File(args[1]), password);
                    if (files.remove(args[2]) != null) {
                        Pit.encryptFromMemory(files, new File(args[1]), password);
                        System.out.println("File removed: " + args[2]);
                    } else {
                        System.err.println("File not found: " + args[2]);
                    }
                } catch (final Exception e) {
                    System.err.println("Failed to remove file!");
                    throw e;
                }
                break;
            case "--edit":
                if (args.length < 4) {
                    System.err.println("Usage: --edit [encrypted file] [file in archive] [new file]");
                    return;
                }

                try {
                    Map<String, byte[]> files = Pit.decryptToMemory(new File(args[1]), password);
                    File newFile = new File(args[3]);
                    try {
                        decryptSingleFileFromArchive(new File(args[1]), args[2], password); // for validation
                    } catch (FileNotFoundException e) {
                        System.err.println("File not found: " + args[2]);
                        return;
                    }
                    files.put(args[2], Files.readAllBytes(newFile.toPath()));
                    Pit.encryptFromMemory(files, new File(args[1]), password);
                    System.out.println("File edited: " + args[2]);
                } catch (Exception e) {
                    System.err.println("Failed to edit file!");
                    throw e;
                }
                break;
            case "--write":
                if (args.length < 3) {
                    System.err.println("Usage: --write [encrypted file] [file name]");
                    return;
                }

                try {
                    Map<String, byte[]> files = Pit.decryptToMemory(new File(args[1]), password);
                    System.out.println("Enter content for " + args[2] + " (end with an empty line):");
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while (!(line = console.readLine()).isEmpty()) {
                        sb.append(line).append(System.lineSeparator());
                    }
                    files.put(args[2], sb.toString().getBytes(StandardCharsets.UTF_8));
                    Pit.encryptFromMemory(files, new File(args[1]), password);
                    System.out.println("File added: " + args[2]);
                } catch (Exception e) {
                    System.err.println("Failed to add inlined file!");
                    throw e;
                }
                break;
            default:
                System.out.println("Unknown mode: " + args[0]);
        }
    }

    private static byte[] decryptEntryContent(final byte[] fullContent, final String password) throws Exception {
        if (fullContent.length < SALT_LENGTH + 16) {
            throw new IllegalArgumentException("Encrypted entry is too short to be valid.");
        }

        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[16];
        System.arraycopy(fullContent, 0, salt, 0, SALT_LENGTH);
        System.arraycopy(fullContent, SALT_LENGTH, iv, 0, 16);
        byte[] encryptedData = new byte[fullContent.length - SALT_LENGTH - 16];
        System.arraycopy(fullContent, SALT_LENGTH + 16, encryptedData, 0, encryptedData.length);

        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(encryptedData);
    }

    public static byte[] decryptSingleFileFromArchive(final File zipFile, final String entryName, final String password) throws Exception {
        try (FileInputStream fis = new FileInputStream(zipFile);
             ZipInputStream zis = new ZipInputStream(fis)) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (!entry.getName().equals(entryName)) continue;

                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                zis.transferTo(buffer);
                return decryptEntryContent(buffer.toByteArray(), password);
            }
        }

        throw new FileNotFoundException("File not found in archive: " + entryName);
    }

    public static Map<String, byte[]> decryptToMemory(final File file, final String password) throws Exception {
        Map<String, byte[]> result = new HashMap<>();

        try (FileInputStream fis = new FileInputStream(file);
             ZipInputStream zis = new ZipInputStream(fis)) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.isDirectory()) continue;

                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                zis.transferTo(buffer);
                byte[] fullContent = buffer.toByteArray();

                try {
                    result.put(entry.getName(), decryptEntryContent(fullContent, password));
                } catch (Exception e) {
                    System.err.println("Failed to decrypt entry: " + entry.getName());
                    throw e;
                }
            }
        }

        return result;
    }


    public static void encryptFromMemory(final Map<String, byte[]> files, final File output, final String password) throws Exception {
        try (final FileOutputStream fos = new FileOutputStream(output);
             final ZipOutputStream zos = new ZipOutputStream(fos)) {

            for (Map.Entry<String, byte[]> entry : files.entrySet()) {
                final byte[] salt = new byte[SALT_LENGTH];
                final byte[] iv = new byte[16];
                new SecureRandom().nextBytes(salt);
                new SecureRandom().nextBytes(iv);

                final SecretKey key = deriveKey(password, salt);
                final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
                final byte[] encryptedData = cipher.doFinal(entry.getValue());

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(salt);
                baos.write(iv);
                baos.write(encryptedData);

                ZipEntry zipEntry = new ZipEntry(entry.getKey());
                zos.putNextEntry(zipEntry);
                zos.write(baos.toByteArray());
                zos.closeEntry();
            }
        }
    }

    public static void encryptFolder(final String folderPath, final String outputFilePath, final String password) throws Exception {
        final File folder = new File(folderPath);
        if (!folder.exists() || !folder.isDirectory()) {
            throw new IllegalArgumentException("Invalid folder: " + folderPath);
        }

        final Map<String, byte[]> files = new HashMap<>();
        loadFilesRecursively(folder, folder.getAbsolutePath(), files);
        encryptFromMemory(files, new File(outputFilePath), password);
    }

    private static void loadFilesRecursively(final File base, final String rootPath, final Map<String, byte[]> map) throws IOException {
        if (base.isDirectory()) {
            for (File file : base.listFiles()) {
                loadFilesRecursively(file, rootPath, map);
            }
        } else {
            final String relPath = base.getAbsolutePath().substring(rootPath.length() + 1).replace("\\", "/");
            map.put(relPath, Files.readAllBytes(base.toPath()));
        }
    }

    public static void decryptToFolder(final String inputFilePath, final String outputFolderPath, final String password) throws Exception {
        final Map<String, byte[]> files = decryptToMemory(new File(inputFilePath), password);
        for (final Map.Entry<String, byte[]> entry : files.entrySet()) {
            final File outFile = new File(outputFolderPath, entry.getKey());
            outFile.getParentFile().mkdirs();
            Files.write(outFile.toPath(), entry.getValue());
        }
    }

    public static SecretKey deriveKey(final String password, final byte[] salt) throws Exception {
        final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        final KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        final SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

}