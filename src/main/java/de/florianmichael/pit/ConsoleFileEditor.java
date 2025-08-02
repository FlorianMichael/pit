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

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.function.Consumer;

import static de.florianmichael.pit.LogUtils.logCommand;
import static de.florianmichael.pit.LogUtils.logError;
import static de.florianmichael.pit.LogUtils.logInfo;
import static de.florianmichael.pit.LogUtils.logSection;
import static de.florianmichael.pit.LogUtils.logSuccess;
import static de.florianmichael.pit.LogUtils.logWarning;

public final class ConsoleFileEditor {

    private static final Scanner scanner = new Scanner(System.in);

    /**
     * Launches a line-based text editor for the given content.
     *
     * @param initialContent The initial lines of the file (unmodifiable if you pass in List.of)
     * @param onSave         A callback that gets called with the updated lines if the user saves
     */
    public static void open(final List<String> initialContent, final Consumer<List<String>> onSave) {
        final List<String> lines = new ArrayList<>(initialContent);
        boolean modified = false;

        while (true) {
            System.out.println("\n--- File Content ---");
            for (int i = 0; i < lines.size(); i++) {
                System.out.printf("%3d | %s%n", i + 1, lines.get(i));
            }

            System.out.print("\nCommand (type `help`): ");
            final String[] input = scanner.nextLine().trim().split("\\s+", 2);
            final String command = input[0].toLowerCase();
            final String arg = input.length > 1 ? input[1] : "";

            switch (command) {
                case "edit", "e" -> {
                    try {
                        final int lineNum = Integer.parseInt(arg) - 1;
                        if (lineNum < 0 || lineNum >= lines.size()) {
                            logError("Invalid line number.");
                            break;
                        }

                        logInfo("New content: ");
                        lines.set(lineNum, scanner.nextLine());
                        modified = true;
                    } catch (final Exception ignored) {
                        logError("Usage: edit <lineNumber>");
                    }
                }

                case "add", "a" -> {
                    logInfo("Content to add: ");
                    lines.add(scanner.nextLine());
                    modified = true;
                }

                case "delete", "del", "d" -> {
                    try {
                        final int lineNum = Integer.parseInt(arg) - 1;
                        if (lineNum < 0 || lineNum >= lines.size()) {
                            logError("Invalid line number.");
                            break;
                        }

                        lines.remove(lineNum);
                        modified = true;
                    } catch (final Exception ignored) {
                        logError("Usage: delete <lineNumber>");
                    }
                }

                case "save", "s" -> {
                    onSave.accept(new ArrayList<>(lines));
                    logSuccess("Changes saved.");
                    modified = false;
                }

                case "exit", "quit", "q" -> {
                    if (modified) {
                        System.out.print("Unsaved changes. Save before exiting? (y/n): ");
                        String choice = scanner.nextLine().trim().toLowerCase();
                        if (choice.equals("y")) {
                            onSave.accept(new ArrayList<>(lines));
                            logSuccess("Saved.");
                        }
                    }
                    logInfo("Goodbye.");
                    return;
                }

                case "help", "h" -> printHelp();

                default -> logWarning("Unknown command. Type `help` for a list.");
            }
        }
    }

    private static void printHelp() {
        logSection("\nAvailable Commands:");
        logCommand("edit", "<line>", "Edit a specific line");
        logCommand("add", "", "Add a new line at the end");
        logCommand("delete", "<line>", "Delete a specific line");
        logCommand("save", "", "Save the changes");
        logCommand("exit", "", "Quit the editor (asks to save if unsaved)");
        logCommand("help", "", "Show this help message");
    }

}
