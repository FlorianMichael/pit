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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public final class ZipWalker {

    public static Node buildZipTree(final ZipInputStream zis) throws IOException {
        final Node root = new Node("", true);
        ZipEntry entry;

        while ((entry = zis.getNextEntry()) != null) {
            String[] parts = entry.getName().split("/");
            Node current = root;

            for (int i = 0; i < parts.length; i++) {
                String part = parts[i];
                boolean isDir = (i < parts.length - 1) || entry.isDirectory();

                current.children.putIfAbsent(part, new Node(part, isDir));
                current = current.children.get(part);
            }

            zis.closeEntry();
        }

        return root;
    }

    public static void printTree(final Node node, final int indent) {
        if (!node.name.isEmpty()) {
            System.out.println("    ".repeat(indent) + node.name);
        }

        final List<Node> sorted = new ArrayList<>(node.children.values());
        sorted.sort(Comparator
            .comparing((Node n) -> !n.isDirectory)
            .thenComparing(n -> n.name.toLowerCase()));
        for (Node child : sorted) {
            printTree(child, indent + 1);
        }
    }

    public static Node findNode(final Node root, final String path) {
        if (path == null || path.isEmpty()) {
            return root;
        }

        final String[] parts = path.split("/");
        Node current = root;
        for (final String part : parts) {
            if (part.isEmpty()) {
                continue;
            }

            current = current.children.get(part);
            if (current == null) {
                return null;
            }
        }
        return current;
    }

    public static class Node {

        final String name;
        final boolean isDirectory;
        final Map<String, Node> children = new TreeMap<>();

        Node(String name, boolean isDirectory) {
            this.name = name;
            this.isDirectory = isDirectory;
        }

    }

}
