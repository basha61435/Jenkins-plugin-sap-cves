package io.jenkins.plugins;

import io.jenkins.plugins.Model.JavaCVEs;
import org.springframework.util.ObjectUtils;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class FindFiles {

    public List<JavaCVEs> getJavaCVEs(String path) {
        List<JavaCVEs> javaCVEsList = new ArrayList<>();
        Path startDir = Paths.get(path);
//        List<String> targetFiles = Arrays.asList("pom.xml", "package.json");
        try {
            Files.walkFileTree(startDir, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
//                    if (file != null && targetFiles.contains(file.getFileName().toString())) {
                        List<String> lines = Files.readAllLines(file);
                        for (String line : lines) {
                            if (line.contains("<artifactId>rate-email</artifactId>")) {
                                JavaCVEs cvEs = new JavaCVEs();
                                cvEs.setFilePath(file.toString());
                                cvEs.setCves("CVE-2023-50422");
                                cvEs.setGroupId(line.trim());
                                javaCVEsList.add(cvEs);
                            }
                        }
//                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            e.printStackTrace();
        }

        return javaCVEsList;
    }
}
