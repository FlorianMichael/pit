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

import javax.swing.*;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.io.File;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public final class PitViewer extends JFrame {

    private final Map<String, byte[]> inMemoryFiles = new HashMap<>();
    private final JTree tree;
    private final JTextArea textArea;

    public PitViewer() {
        setTitle("Private Information Tracker");
        setSize(800, 600);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        final DefaultMutableTreeNode root = new DefaultMutableTreeNode("Data");
        tree = new JTree(root);
        tree.addTreeSelectionListener(new TreeSelectionListener() {
            public void valueChanged(final TreeSelectionEvent e) {
                TreePath path = tree.getSelectionPath();
                if (path == null) return;
                String fullPath = path.getLastPathComponent().toString();
                byte[] data = inMemoryFiles.get(fullPath);
                textArea.setText(data == null ? "" : new String(data));
            }
        });

        textArea = new JTextArea();
        textArea.setEditable(false);

        final JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(tree), new JScrollPane(textArea));
        splitPane.setDividerLocation(200);
        add(splitPane, BorderLayout.CENTER);

        final JMenuBar menuBar = new JMenuBar();
        final JMenu fileMenu = new JMenu("File");
        final JMenuItem loadEncrypted = new JMenuItem("Load encrypted file");
        loadEncrypted.addActionListener(e -> loadEncryptedFile());
        fileMenu.add(loadEncrypted);

        final JMenuItem saveEncrypted = new JMenuItem("Save as...");
        saveEncrypted.addActionListener(e -> saveEncryptedData());
        fileMenu.add(saveEncrypted);

        final JMenu gitHubMenu = new JMenu("GitHub");
        final JMenuItem openGitHub = new JMenuItem("Open GitHub Repository");
        openGitHub.addActionListener(ignored -> {
            try {
                Desktop.getDesktop().browse(new URI("https://github.com/FlorianMichael/pit"));
            } catch (final Exception e) {
                JOptionPane.showMessageDialog(this, "Failed to open GitHub repository:\n" + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        gitHubMenu.add(openGitHub);

        menuBar.add(fileMenu);
        menuBar.add(gitHubMenu);
        setJMenuBar(menuBar);

        setVisible(true);

        final File defaultFile = new File("passwords");
        if (defaultFile.exists()) {
            int load = JOptionPane.showConfirmDialog(this, "Found 'passwords'. Load it?", "Auto Load", JOptionPane.YES_NO_OPTION);
            if (load == JOptionPane.YES_OPTION) {
                loadEncryptedFile(defaultFile);
            }
        }
    }

    private void loadEncryptedFile() {
        final JFileChooser chooser = new JFileChooser();
        final int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        loadEncryptedFile(chooser.getSelectedFile());
    }

    private void loadEncryptedFile(final File file) {
        final JPasswordField passwordField = new JPasswordField();
        final int option = JOptionPane.showConfirmDialog(this, passwordField, "Enter master password", JOptionPane.OK_CANCEL_OPTION);
        if (option != JOptionPane.OK_OPTION) {
            return;
        }

        final String password = new String(passwordField.getPassword());
        if (password.isEmpty()) {
            return;
        }

        try {
            inMemoryFiles.clear();
            inMemoryFiles.putAll(Pit.decryptToMemory(file, password));
            updateTree();
        } catch (final Exception e) {
            JOptionPane.showMessageDialog(this, "Decryption failed.\nCheck your password or ensure the file is valid.", "Decryption Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void saveEncryptedData() {
        if (inMemoryFiles.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No data to save.", "Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        final JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("passwords"));
        final int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        final File outputFile = chooser.getSelectedFile();

        final JPasswordField passwordField = new JPasswordField();
        final int option = JOptionPane.showConfirmDialog(this, passwordField, "Enter password to encrypt with", JOptionPane.OK_CANCEL_OPTION);
        if (option != JOptionPane.OK_OPTION) {
            return;
        }

        final String password = new String(passwordField.getPassword());
        if (password.isEmpty()) {
            return;
        }

        try {
            Pit.encryptFromMemory(inMemoryFiles, outputFile, password);
            JOptionPane.showMessageDialog(this, "Data saved to: " + outputFile.getAbsolutePath(), "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (final Exception e) {
            JOptionPane.showMessageDialog(this, "Failed to save data:\n" + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void updateTree() {
        final DefaultMutableTreeNode root = new DefaultMutableTreeNode("Data");
        for (final String name : inMemoryFiles.keySet()) {
            root.add(new DefaultMutableTreeNode(name));
        }
        tree.setModel(new DefaultTreeModel(root));
    }

}
