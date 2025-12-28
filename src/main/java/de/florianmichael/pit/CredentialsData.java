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

import static de.florianmichael.pit.LogUtils.logError;

public record CredentialsData(String email, String password, String extra) {

    public static CredentialsData parseCredentials(final byte[] content) {
        final String text = new String(content);
        final String[] lines = text.split("\r?\n");

        String email = "";
        String password = null;
        StringBuilder extraBuilder = new StringBuilder();

        boolean extraSection = false;
        for (String rawLine : lines) {
            final String line = rawLine.trim();
            if (!extraSection) {
                if (line.toLowerCase().startsWith("email:")) {
                    email = line.substring("email:".length()).trim();
                } else if (line.toLowerCase().startsWith("password:")) {
                    password = line.substring("password:".length()).trim();
                } else if (line.toLowerCase().startsWith("extra:")) {
                    extraSection = true;
                    final String rest = line.substring("extra:".length());
                    if (!rest.isEmpty()) {
                        extraBuilder.append(rest.trim()).append(System.lineSeparator());
                    }
                }
            } else {
                extraBuilder.append(rawLine).append(System.lineSeparator());
            }
        }

        if (password == null || password.isEmpty()) {
            logError("Invalid .credentials format: missing or empty password field.");
            return null;
        }

        final String extra = extraBuilder.toString().trim();
        return new CredentialsData(email, password, extra);
    }

}
