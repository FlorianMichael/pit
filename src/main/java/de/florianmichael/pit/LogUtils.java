/*
 * This file is part of pit - https://github.com/FlorianMichael/pit
 * Copyright (C) 2025-2026 FlorianMichael/EnZaXD <git@florianmichael.de> and contributors
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

import org.fusesource.jansi.Ansi;

import static org.fusesource.jansi.Ansi.ansi;

public final class LogUtils {

    public static void logAsciiArt() {
        System.out.println("""
             ____        ______      ______  \s
            /\\  _`\\     /\\__  _\\    /\\__  _\\ \s
            \\ \\ \\L\\ \\   \\/_/\\ \\/    \\/_/\\ \\/ \s
             \\ \\ ,__/      \\ \\ \\       \\ \\ \\ \s
              \\ \\ \\/        \\_\\ \\__     \\ \\ \\\s
               \\ \\_\\        /\\_____\\     \\ \\_\\
                \\/_/        \\/_____/      \\/_/
            """);
        System.out.println("https://github.com/FlorianMichael/pit");
        System.out.println();
    }

    public static void logInfo(final String msg) {
        System.out.println(ansi().fgCyan().a(msg).reset());
    }

    public static void logSuccess(final String msg) {
        System.out.println(ansi().fgGreen().a(msg).reset());
    }

    public static void logWarning(final String msg) {
        System.out.println(ansi().fgYellow().a(msg).reset());
    }

    public static void logError(final String msg) {
        System.err.println(ansi().fgRed().a(msg).reset());
    }

    public static void logSection(final String title) {
        System.out.println(ansi().bold().fg(Ansi.Color.WHITE).a(title).reset());
    }

    public static void logCommand(final String names, final String args, final String desc) {
        final String command = String.format("   %-20s %-30s %s", names, args, desc);
        System.out.println(ansi().fgBrightBlack().a(command).reset());
    }

}
