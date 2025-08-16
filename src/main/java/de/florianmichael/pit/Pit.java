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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Scanner;
import org.fusesource.jansi.AnsiConsole;

import static de.florianmichael.pit.LogUtils.logCommand;
import static de.florianmichael.pit.LogUtils.logError;
import static de.florianmichael.pit.LogUtils.logInfo;
import static de.florianmichael.pit.LogUtils.logSection;
import static de.florianmichael.pit.LogUtils.logSuccess;
import static de.florianmichael.pit.LogUtils.logWarning;
import static org.fusesource.jansi.Ansi.ansi;

public final class Pit {

    private static String RANDOM_STRING;

    private static File vault = null;
    private static byte[] key = null;

    public static void main(final String[] programArgs) {
        AnsiConsole.systemInstall();
        Runtime.getRuntime().addShutdownHook(new Thread(AnsiConsole::systemUninstall));

        LogUtils.logAsciiArt();

        final Console console = System.console();
        if (console == null) {
            logError("Pit requires a console to run. Please run it in a terminal.");
            return;
        }

        if (programArgs.length < 2) {
            logSection("Usage:");
            logCommand("init, i", "<name>", "Initialize a new encrypted vault");
            logCommand("encrypt, e", "<folder> <vault>", "Encrypt a folder into a vault");
            logCommand("session, s", "<vault>", "Load an existing vault");
            return;
        }

        final String action = programArgs[0];
        final String[] args = Arrays.copyOfRange(programArgs, 1, programArgs.length);
        switch (action) {
            case "init", "i" -> init(args);
            case "encrypt", "e" -> encrypt(args);
            case "session", "s" -> session(args, null);
        }
    }

    private static void init(final String[] args) {
        if (args.length != 1) {
            logError("Usage: init <file path>");
            return;
        }

        final String filePath = args[0];
        if (Files.exists(Path.of(filePath))) {
            logWarning("File already exists: " + filePath);
            logInfo("If you want to reinitialize it, please delete the existing vault file first.");
            return;
        }

        final String password = confirmPassword();

        try {
            FileUtils.encryptVault(new HashMap<>(), new File(filePath), password);
            logSuccess("Vault initialized successfully: " + filePath);

            session(args, password);
        } catch (final Exception e) {
            logError("Failed to initialize vault: " + e.getMessage());
        }
    }

    private static void encrypt(final String[] args) {
        if (args.length != 2) {
            logError("Usage: encrypt <folder path> <file path>");
            return;
        }

        final String folderPath = args[0];
        if (!Files.isDirectory(Path.of(folderPath))) {
            logError("Invalid folder path: " + folderPath);
            return;
        }

        final String filePath = args[1];
        if (Files.exists(Path.of(filePath))) {
            logWarning("File already exists: " + filePath);
            logInfo("If you want to overwrite it, please delete the existing file first.");
            return;
        }

        final String password = confirmPassword();

        try {
            final File folder = new File(folderPath);
            final Map<String, byte[]> files = new HashMap<>();
            loadFilesRecursively(folder, folder.getAbsolutePath(), files);
            FileUtils.encryptVault(files, new File(filePath), password);
            logSuccess("File encrypted successfully: " + filePath);
        } catch (final Exception e) {
            logError("Failed to encrypt file: " + e.getMessage());
        }
    }

    private static void session(final String[] programArgs, String password) {
        vault = new File(programArgs[0]);
        if (!vault.exists()) {
            logError("Vault file does not exist: " + vault);
            return;
        }

        if (password == null) {
            final char[] bytes = System.console().readPassword("Enter master password: ");
            if (bytes == null) {
                logError("No master password provided. Please try again.");
                return;
            }

            password = new String(bytes);
            if (password.isEmpty()) {
                logError("Master password cannot be empty. Please try again.");
                return;
            }
        }

        final ZipWalker.Node node = ZipWalker.getNode(vault, password, "");
        if (node == null) {
            return;
        }

        try {
            final byte[] randomBytes = new byte[16];
            new SecureRandom().nextBytes(randomBytes);
            RANDOM_STRING = new String(randomBytes);

            key = EncryptUtils.encryptBytes(password.getBytes(), RANDOM_STRING);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }

        help();

        final Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.print(ansi().fgBrightBlue().bold().a(vault.getName()).reset() + " > ");
            final String[] input;
            try {
                input = scanner.nextLine().trim().split("\\s+");
            } catch (final Exception e) {
                break;
            }

            final String command = input.length > 0 ? input[0].toLowerCase() : "";
            final String[] args = Arrays.copyOfRange(input, 1, input.length);
            switch (command) {
                case "help", "h" -> help();
                case "init", "i" -> init(args);
                case "encrypt", "e" -> encrypt(args);
                case "decrypt", "d" -> decrypt(args);
                case "view", "v" -> view(args);
                case "remove", "r" -> remove(args);
                case "rename", "rn" -> rename(args);
                case "edit", "et" -> edit(args);
                case "create", "c" -> create(args);
                case "add", "a" -> add(args);
                case "generate", "g" -> generate(args);
                case "recrypt", "rc" -> recrypt(args);
                case "key", "kl" -> setKeyLength(args);
                case "clear", "cls" -> clearConsole();
                case "exit", "quit" -> {
                    logInfo("Exiting pit. Goodbye!");
                    System.exit(0);
                    return;
                }
                default -> {
                    logWarning("Unknown command: " + command);
                    logInfo("Use help or h for usage information.");
                }
            }
        }
    }

    private static void help() {
        logSection("Usage:");
        logCommand("help, h", "", "Show this help dialog");
        logCommand("key, kl", "[<key length>] [<iterations>]", "Set the key length for encryption");
        logCommand("exit, quit", "", "Exit the program");
        logCommand("clear, cls", "", "Clear the console & clipboard");
        logCommand("decrypt, d", "<folder>", "Decrypt a vault to a folder");
        logCommand("recrypt, rc", "", "Re-encrypt the vault with a new password");
        logCommand("view, v", "[<entry>]", "View a file/folder inside a vault");
        logCommand("remove, r", "<entry>", "Remove a file/folder from a vault");
        logCommand("rename, rn", "<entry> <new name>", "Rename an entry in a vault");
        logCommand("edit, et", "<entry>", "Edit a file in the vault");
        logCommand("create, c", "<entry>", "Create a new entry in a vault");
        logCommand("add, a", "<file>", "Add an external file to the vault");
        logCommand("generate, g", "<name>", "Generate a credentials entry");
        System.out.println();
    }

    private static void decrypt(final String[] args) {
        if (args.length != 1) {
            logError("Usage: decrypt <folder path>");
            return;
        }

        final Path folderPath = Path.of(args[0]);
        if (Files.exists(folderPath)) {
            logWarning("Folder already exists: " + folderPath);
            logInfo("If you want to overwrite it, please delete the existing folder first.");
            return;
        }

        final String password = masterPassword();

        try {
            final Map<String, byte[]> files = FileUtils.decryptVault(vault, password);
            final Path outputBasePath = folderPath.toAbsolutePath().normalize();

            for (final Map.Entry<String, byte[]> entry : files.entrySet()) {
                final Path outPath = outputBasePath.resolve(entry.getKey()).normalize();
                if (!outPath.startsWith(outputBasePath)) {
                    throw new SecurityException("Invalid path: " + entry.getKey());
                }

                Files.createDirectories(outPath.getParent());
                Files.write(outPath, entry.getValue());
            }
            logSuccess("File decrypted successfully to: " + folderPath);
        } catch (final Exception e) {
            logError("Failed to decrypt file: " + e.getMessage());
        }
    }

    private static void view(final String[] args) {
        if (args.length > 1) {
            logError("Usage: view (folder/file in archive)");
            return;
        }

        final String entryPath = args.length == 1 ? args[0].replace("\\", "/") : "";
        final String password = masterPassword();

        final ZipWalker.Node node = ZipWalker.getNode(vault, password, entryPath);
        if (node == null) {
            logError("Entry not found: " + entryPath);
            return;
        }

        if (node.isDirectory) {
            logInfo("Contents of folder " + (entryPath.isEmpty() ? "/" : entryPath) + ":");
            ZipWalker.printNodeTree(node, 0);
            return;
        }

        try {
            final byte[] content = FileUtils.decryptEntry(vault, entryPath, password);
            logInfo("Content of " + entryPath + ":");
            System.out.println(new String(content));
        } catch (final Exception e) {
            logError("Failed to read archive: " + e.getMessage());
        }
    }

    private static void remove(final String[] args) {
        if (args.length < 1 || args.length > 2) {
            logError("Usage: remove <folder/file in archive>");
            return;
        }

        final String confirm = new String(System.console().readPassword("Are you sure you want to remove the entry? Type 'yes' to confirm: "));
        if (!"yes".equalsIgnoreCase(confirm)) {
            logSuccess("Removal cancelled.");
            return;
        }

        final String entryPath = args[0].replace("\\", "/");
        final String password = masterPassword();

        try {
            FileUtils.removeEntry(vault, entryPath, password);
            logSuccess("Entry removed successfully: " + entryPath);
        } catch (final Exception e) {
            logError("Failed to remove entry: " + e.getMessage());
        }
    }

    private static void rename(final String[] args) {
        if (args.length != 2) {
            logError("Usage: rename <folder/file in archive> <new name>");
            return;
        }

        final String oldName = args[0].replace("\\", "/");
        final String newName = args[1].replace("\\", "/");
        final String password = masterPassword();

        try {
            FileUtils.renameEntry(vault, oldName, newName, password);
            logSuccess("Entry renamed successfully to: " + newName);
        } catch (final Exception e) {
            logError("Failed to rename entry: " + e.getMessage());
        }
    }

    private static void edit(final String[] args) {
        if (args.length != 1) {
            logError("Usage: edit <folder/file in archive>");
            return;
        }

        final String entryPath = args[0].replace("\\", "/");
        final String password = masterPassword();

        try {
            final byte[] content = FileUtils.decryptEntry(vault, entryPath, password);
            ConsoleFileEditor.open(new String(content).lines().toList(), updatedLines -> {
                try {
                    final byte[] newContent = String.join("\n", updatedLines).getBytes();
                    FileUtils.editEntry(vault, entryPath, newContent, password);
                    logSuccess("Entry edited successfully.");
                } catch (final Exception e) {
                    logError("Failed to save changes: " + e.getMessage());
                }
            });
        } catch (final Exception e) {
            logError("Failed to edit entry: " + e.getMessage());
        }
    }

    private static void create(final String[] args) {
        if (args.length != 1) {
            logError("Usage: create <folder/file name>");
            return;
        }

        final String entryName = args[0].replace("\\", "/");
        final String password = masterPassword();

        try {
            StringBuilder sb = new StringBuilder();
            String line;
            while (!(line = System.console().readLine()).isEmpty()) {
                sb.append(line).append(System.lineSeparator());
            }
            final String content = sb.toString().trim();
            FileUtils.addEntry(vault, entryName, content.getBytes(), password);
            logSuccess("Entry created successfully: " + entryName);
        } catch (final Exception e) {
            logError("Failed to create entry: " + e.getMessage());
        }
    }

    private static void add(final String[] args) {
        if (args.length != 1) {
            logError("Usage: add <folder/file path>");
            return;
        }

        final String entryPath = args[0].replace("\\", "/");
        final String password = masterPassword();

        try {
            final String content = new String(Files.readAllBytes(Path.of(entryPath)));
            FileUtils.addEntry(vault, entryPath, content.getBytes(), password);
            logSuccess("Entry added successfully: " + entryPath);
        } catch (final Exception e) {
            logError("Failed to add entry: " + e.getMessage());
        }
    }

    private static void generate(final String[] args) {
        if (args.length != 1) {
            logError("Usage: generate <file name>");
            return;
        }

        final String fileName = args[0].replace("\\", "/");
        final String password = KeyUtils.generateRandomPassword();

        try {
            FileUtils.addEntry(vault, fileName, password.getBytes(), masterPassword());
            logSuccess("Generated password: " + password);
            copyToClipboard(password);
            logInfo("Password copied to clipboard.");
        } catch (final Exception e) {
            logError("Failed to generate password: " + e.getMessage());
        }
    }

    private static void recrypt(final String[] args) {
        if (args.length > 1) {
            logError("Usage: recrypt");
            return;
        }

        final String oldPassword = masterPassword();
        final String newPassword = confirmPassword();

        try {
            final Map<String, byte[]> file = FileUtils.decryptVault(vault, oldPassword);
            FileUtils.encryptVault(file, vault, newPassword);
            file.clear();
            logInfo("Vault re-encrypted successfully.");
        } catch (final Exception e) {
            logError("Failed to re-encrypt vault: " + e.getMessage());
        }
    }

    private static void setKeyLength(final String[] args) {
        if (args.length < 1 || args.length > 2) {
            KeyUtils.ITERATIONS = 65536;
            KeyUtils.KEY_LENGTH = 256;
            logInfo("Using default key length of 256 bits and 65536 iterations.");
            return;
        }

        final int keyLength;
        try {
            keyLength = Integer.parseInt(args[0]);
        } catch (final NumberFormatException e) {
            logError("Invalid key length: " + args[0]);
            return;
        }

        final int iterations = args.length == 2 ? Integer.parseInt(args[1]) : 65536;
        if (keyLength <= 0 || iterations <= 0) {
            logError("Key length and iteration count must be positive integers.");
            return;
        }

        KeyUtils.ITERATIONS = iterations;
        KeyUtils.KEY_LENGTH = keyLength;
        logSuccess("Key length set to " + keyLength + " bits with " + iterations + " iterations.");
    }

    private static void clearConsole() {
        copyToClipboard("");

        final String os = System.getProperty("os.name");

        try {
            if (os.contains("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } else {
                new ProcessBuilder("clear").inheritIO().start().waitFor();
            }
        } catch (final IOException | InterruptedException e) {
            logError("Failed to clear console: " + e.getMessage());
        }
    }

    // 

    private static String masterPassword() {
        try {
            return new String(EncryptUtils.decryptBytes(key, RANDOM_STRING));
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String confirmPassword() {
        final String password = new String(System.console().readPassword("Enter master password: "));
        final String confirm = new String(System.console().readPassword("Confirm master password: "));
        if (!confirm.equals(password)) {
            logWarning("Passwords do not match. Please try again.");
            return confirmPassword();
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

    private static void loadFilesRecursively(final File base, final String rootPath, final Map<String, byte[]> map) throws IOException {
        if (base.isDirectory()) {
            for (File file : Objects.requireNonNull(base.listFiles())) {
                loadFilesRecursively(file, rootPath, map);
            }
        } else {
            String relativePath = base.getAbsolutePath().substring(rootPath.length() + 1).replace("\\", "/");
            map.put(relativePath, Files.readAllBytes(base.toPath()));
        }
    }

}
