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

import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import org.fusesource.jansi.AnsiConsole;

import static de.florianmichael.pit.LogUtils.logCommand;
import static de.florianmichael.pit.LogUtils.logError;
import static de.florianmichael.pit.LogUtils.logInfo;
import static de.florianmichael.pit.LogUtils.logSection;
import static de.florianmichael.pit.LogUtils.logSubsection;
import static de.florianmichael.pit.LogUtils.logSuccess;
import static de.florianmichael.pit.LogUtils.logWarning;
import static org.fusesource.jansi.Ansi.ansi;

public final class Pit {

    public static void main(final String[] args) {
        if (args.length == 0) {
            logError("Usage: pit <file> [<file>...]");
            return;
        }

        final Console console = System.console();
        if (console == null) {
            logError("Pit requires a console to run. Please run it in a terminal.");
            return;
        }

        AnsiConsole.systemInstall();
        Runtime.getRuntime().addShutdownHook(new Thread(AnsiConsole::systemUninstall));

        final String command = args[0].toLowerCase();
        switch (command) {
            case "--help", "-h" -> printHelp();
            case "--init", "-i" -> {
                if (args.length != 2) {
                    logError("Usage: pit --init <file path>");
                    return;
                }

                final String filePath = args[1];
                if (Files.exists(Path.of(filePath))) {
                    logWarning("File already exists: " + filePath);
                    logInfo("If you want to reinitialize it, please delete the existing vault file first.");
                    return;
                }

                final String password = confirmPassword(requestPassword());

                try {
                    FileUtils.encrypt(new HashMap<>(), new File(filePath), password);
                    logSuccess("Vault initialized successfully: " + filePath);
                } catch (final Exception e) {
                    logError("Failed to initialize vault: " + e.getMessage());
                }
            }
            case "--encrypt", "-e" -> {
                if (args.length != 3) {
                    logError("Usage: pit --encrypt <folder path> <file path>");
                    return;
                }

                final String folderPath = args[1];
                if (!Files.isDirectory(Path.of(folderPath))) {
                    logError("Invalid folder path: " + folderPath);
                    return;
                }

                final String filePath = args[2];
                if (Files.exists(Path.of(filePath))) {
                    logWarning("File already exists: " + filePath);
                    logInfo("If you want to overwrite it, please delete the existing file first.");
                    return;
                }

                final String password = confirmPassword(requestPassword());

                try {
                    FileUtils.encryptVault(folderPath, filePath, password);
                    logSuccess("File encrypted successfully: " + filePath);
                } catch (final Exception e) {
                    logError("Failed to encrypt file: " + e.getMessage());
                }
            }
            case "--decrypt", "-d" -> {
                if (args.length != 3) {
                    logError("Usage: pit --decrypt <file path> <folder path>");
                    return;
                }

                final String filePath = args[1];
                final String folderPath = args[2];
                final String password = requestPassword();

                try {
                    FileUtils.decryptVault(filePath, folderPath, password);
                    logSuccess("File decrypted successfully to: " + folderPath);
                } catch (final Exception e) {
                    logError("Failed to decrypt file: " + e.getMessage());
                }
            }
            case "--view", "-v" -> {
                if (args.length < 2) {
                    logError("Usage: pit --view <file path> (folder/file in archive)");
                    return;
                }

                final String filePath = args[1];
                final String entryPath = args.length > 2 ? args[2].replace("\\", "/") : "";

                try (final ZipInputStream zis = new ZipInputStream(new FileInputStream(filePath))) {
                    final ZipWalker.Node root = ZipWalker.buildZipTree(zis);

                    final ZipWalker.Node node = ZipWalker.findNode(root, entryPath);
                    if (node == null) {
                        logError("Entry not found: " + entryPath);
                        return;
                    }

                    if (node.isDirectory) {
                        logInfo("Contents of folder " + (entryPath.isEmpty() ? "/" : entryPath) + ":");
                        ZipWalker.printTree(node, 0);
                    } else {
                        final String password = requestPassword();
                        final byte[] content = FileUtils.decrypt(new File(filePath), entryPath, password);
                        logInfo("Content of " + entryPath + ":");
                        System.out.println(new String(content));
                    }
                } catch (final Exception e) {
                    logError("Failed to read archive: " + e.getMessage());
                }
            }
            case "--remove", "-r" -> {
                if (args.length < 3) {
                    logError("Usage: pit --remove <file path> <folder/file in archive>");
                    return;
                }

                final String confirm = new String(System.console().readPassword("Are you sure you want to remove the entry? Type 'yes' to confirm: "));
                if (!"yes".equalsIgnoreCase(confirm)) {
                    logSuccess("Removal cancelled.");
                    return;
                }

                remove(args);
            }
            case "--rename", "-rn" -> {
                if (args.length != 4) {
                    logError("Usage: pit --rename <file path> <folder/file in archive> <new name>");
                    return;
                }

                final String filePath = args[1];
                if (!Files.exists(Path.of(filePath))) {
                    logError("File does not exist: " + filePath);
                    return;
                }

                final String oldName = args[2].replace("\\", "/");
                final String newName = args[3].replace("\\", "/");

                try {
                    renameEntry(filePath, oldName, newName);
                    logSuccess("Entry renamed successfully to: " + newName);
                } catch (final Exception e) {
                    logError("Failed to rename entry: " + e.getMessage());
                }
            }
            case "--edit", "-et" -> {
                if (args.length != 3) {
                    logError("Usage: pit --edit <file path> <folder/file in archive>");
                    return;
                }

                final String filePath = args[1];
                final String entryPath = args[2].replace("\\", "/");

                try (final ZipInputStream zis = new ZipInputStream(new FileInputStream(filePath))) {
                    final ZipWalker.Node root = ZipWalker.buildZipTree(zis);
                    final ZipWalker.Node node = ZipWalker.findNode(root, entryPath);

                    if (node == null || node.isDirectory) {
                        logError("Entry not found or is a directory: " + entryPath);
                        return;
                    }

                    final String password = requestPassword();
                    final byte[] content = FileUtils.decrypt(new File(filePath), entryPath, password);
                    ConsoleFileEditor.open(new String(content).lines().toList(), updatedLines -> {
                        try {
                            final byte[] newContent = String.join("\n", updatedLines).getBytes();
                            FileUtils.encrypt(new HashMap<>() {{
                                put(entryPath, newContent);
                            }}, new File(filePath), password);
                            logSuccess("Entry edited successfully.");
                        } catch (final Exception e) {
                            logError("Failed to save changes: " + e.getMessage());
                        }
                    });
                } catch (final Exception e) {
                    logError("Failed to edit entry: " + e.getMessage());
                }
            }
            case "--create", "-c" -> {
                if (args.length != 3) {
                    logError("Usage: pit --create <file path> <folder/file name>");
                    return;
                }

                final String filePath = args[1];
                if (!Files.exists(Path.of(filePath))) {
                    logError("File does not exist: " + filePath);
                    return;
                }

                final String entryName = args[2].replace("\\", "/");
                try {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while (!(line = console.readLine()).isEmpty()) {
                        sb.append(line).append(System.lineSeparator());
                    }
                    final String content = sb.toString().trim();
                    final String password = requestPassword();
                    FileUtils.encrypt(new HashMap<>() {{
                        put(entryName, content.getBytes());
                    }}, new File(filePath), password);
                    logSuccess("Entry created successfully: " + entryName);
                } catch (final Exception e) {
                    logError("Failed to create entry: " + e.getMessage());
                }
            }
            case "--add", "-a" -> {
                if (args.length != 3) {
                    logError("Usage: pit --add <file path> <folder/file path>");
                    return;
                }

                final String filePath = args[1];
                final String entryPath = args[2].replace("\\", "/");

                if (!Files.exists(Path.of(filePath))) {
                    logError("File does not exist: " + filePath);
                    return;
                }

                try {
                    final String content = new String(Files.readAllBytes(Path.of(entryPath)));
                    final String password = requestPassword();
                    FileUtils.encrypt(new HashMap<>() {{
                        put(entryPath, content.getBytes());
                    }}, new File(filePath), password);
                    logSuccess("Entry added successfully: " + entryPath);
                } catch (final Exception e) {
                    logError("Failed to add entry: " + e.getMessage());
                }
            }
            case "--generate", "-g" -> {
                if (args.length != 3) {
                    logError("Usage: pit --generate <file path> <file name>");
                    return;
                }

                final String filePath = args[1];
                if (!Files.exists(Path.of(filePath))) {
                    logError("File does not exist: " + filePath);
                    return;
                }

                final String fileName = args[2].replace("\\", "/");
                try {
                    final String password = KeyUtils.generateRandomPassword();
                    FileUtils.encrypt(new HashMap<>() {{
                        put(fileName, password.getBytes());
                    }}, new File(filePath), requestPassword());
                    logSuccess("Generated password: " + password);
                    copyToClipboard(password);
                    logInfo("Password copied to clipboard.");
                } catch (final Exception e) {
                    logError("Failed to generate password: " + e.getMessage());
                }
            }
            case "--recrypt", "-rc" -> {
                if (args.length != 2) {
                    logError("Usage: pit --recrypt <file path>");
                    return;
                }

                final String filePath = args[1];
                if (!Files.exists(Path.of(filePath))) {
                    logError("File does not exist: " + filePath);
                    return;
                }

                try {
                    final String oldPassword = requestPassword();
                    final String newPassword = confirmPassword(requestPassword());
                    final Map<String, byte[]> vault = FileUtils.decrypt(new File(filePath), oldPassword);
                    FileUtils.encrypt(vault, new File(filePath), newPassword);
                    vault.clear();
                    logInfo("Vault re-encrypted successfully.");
                } catch (final Exception e) {
                    logError("Failed to re-encrypt vault: " + e.getMessage());
                }
            }
            case "--key", "-kl" -> {
                if (args.length < 2 || args.length > 3) {
                    logError("Usage: pit --key <key length> [iteration count]");
                    return;
                }

                final int keyLength;
                try {
                    keyLength = Integer.parseInt(args[1]);
                } catch (final NumberFormatException e) {
                    logError("Invalid key length: " + args[1]);
                    return;
                }

                final int iterations = args.length == 3 ? Integer.parseInt(args[2]) : 65536;

                if (keyLength <= 0 || iterations <= 0) {
                    logError("Key length and iteration count must be positive integers.");
                    return;
                }

                logSuccess("Key length set to " + keyLength + " bits with " + iterations + " iterations.");
                KeyUtils.ITERATIONS = iterations;
                KeyUtils.KEY_LENGTH = keyLength;
            }
            default -> {
                logWarning("Unknown command: " + command);
                logInfo("Use --help or -h for usage information.");
            }
        }
    }

    private static void printHelp() {
        System.out.println(ansi().fgBrightBlue().bold().a("Pit").reset().a(" - https://github.com/FlorianMichael/pit"));
        System.out.println();

        logSection("Usage:");
        logCommand("--help, -h", "", "Show this help dialog");

        logSubsection("To setup your first vault");
        logCommand("--init, -i", "<name>", "Initialize a new encrypted vault");

        logSubsection("You can later encrypt and decrypt the entire vault...");
        logCommand("--encrypt, -e", "<folder> <vault>", "Encrypt a folder into a vault");
        logCommand("--decrypt, -d", "<vault> <folder>", "Decrypt a vault to a folder");

        logSubsection("...or manage individual entries inside the vault using high-level commands:");
        logCommand("--view, -v", "<vault> <entry>", "View a file/folder inside a vault");
        logCommand("--remove, -r", "<vault> <entry>", "Remove a file/folder from a vault");
        logCommand("--rename, -rn", "<vault> <entry> <new name>", "Rename an entry in a vault");
        logCommand("--edit, -et", "<vault> <entry>", "Edit a file in the vault");
        logCommand("--create, -c", "<vault> <entry>", "Create a new entry in a vault");
        logCommand("--add, -a", "<vault> <file>", "Add an external file to the vault");
        logCommand("--generate, -g", "<vault> <name>", "Generate a credentials entry");
        System.out.println();
    }

    private static void remove(final String[] args) {
        final File zipFile = new File(args[1]);
        final String removePath = args[2].replace("\\", "/");

        if (!zipFile.exists()) {
            logError("ZIP file does not exist: " + zipFile);
            return;
        }

        File tempFile;
        try {
            tempFile = File.createTempFile("pit_remove_", ".zip");
            tempFile.deleteOnExit();
        } catch (final IOException e) {
            logError("Failed to create temp file: " + e.getMessage());
            return;
        }

        try (final ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
             final ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(tempFile))) {

            ZipEntry entry;
            boolean found = false;

            while ((entry = zis.getNextEntry()) != null) {
                final String name = entry.getName();
                if (removePath.endsWith("/") ? name.startsWith(removePath) : name.equals(removePath)) {
                    found = true;
                } else {
                    zos.putNextEntry(new ZipEntry(name));
                    zis.transferTo(zos);
                    zos.closeEntry();
                }

                zis.closeEntry();
            }

            if (!found) {
                logError("Entry not found to remove: " + removePath);
                return;
            }

        } catch (final IOException e) {
            logError("Error processing ZIP file: " + e.getMessage());
            return;
        }

        if (!zipFile.delete()) {
            logError("Failed to delete original ZIP file.");
            return;
        }

        if (!tempFile.renameTo(zipFile)) {
            logError("Failed to rename temp file.");
            return;
        }

        logSuccess("Removed " + removePath + " from archive successfully.");
    }

    private static void renameEntry(final String filePath, final String oldName, final String newName) {
        try (final ZipInputStream zis = new ZipInputStream(new FileInputStream(filePath));
             final ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(filePath + ".tmp"))) {

            ZipEntry entry;
            boolean renamed = false;

            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals(oldName)) {
                    zos.putNextEntry(new ZipEntry(newName));
                    renamed = true;
                } else {
                    zos.putNextEntry(new ZipEntry(entry.getName()));
                }

                zis.transferTo(zos);
                zos.closeEntry();
                zis.closeEntry();
            }

            if (!renamed) {
                logError("Entry not found to rename: " + oldName);
                return;
            }

        } catch (final IOException e) {
            logError("Error processing ZIP file: " + e.getMessage());
            return;
        }

        // Replace original file with the modified one
        final File originalFile = new File(filePath);
        final File tempFile = new File(filePath + ".tmp");

        if (!originalFile.delete()) {
            logError("Failed to delete original ZIP file.");
            return;
        }

        if (!tempFile.renameTo(originalFile)) {
            logError("Failed to rename temp file.");
            return;
        }

        logSuccess("Renamed " + oldName + " to " + newName + " successfully.");
    }

    // ----

    private static String requestPassword() {
        final String password = new String(System.console().readPassword("Enter master password: "));
        return password.isEmpty() ? requestPassword() : password;
    }

    private static String confirmPassword(final String password) {
        final String confirm = new String(System.console().readPassword("Confirm master password: "));
        if (!confirm.equals(password)) {
            logWarning("Passwords do not match. Please try again.");
            return confirmPassword(requestPassword());
        }

        return confirm;
    }

    private static void copyToClipboard(final String text) {
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        } catch (Exception e) {
            logError("Failed to copy password to clipboard.");
        }
    }

}
