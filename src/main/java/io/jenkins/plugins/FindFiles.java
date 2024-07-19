package io.jenkins.plugins;

import io.jenkins.plugins.Model.JavaCVEs;
import org.springframework.util.ObjectUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
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

import static org.codehaus.groovy.runtime.StringGroovyMethods.isInteger;

//import static org.codehaus.groovy.runtime.StringGroovyMethods.isInteger;

public class FindFiles {

    public List<JavaCVEs> getJavaCVEs(String path) {
        List<JavaCVEs> javaCVEsList = new ArrayList<>();
        Path startDir = Paths.get(path);
        List<String> targetFiles = Arrays.asList("pom.xml", "package.json");
        try {
            Files.walkFileTree(startDir, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    if (file != null && targetFiles.contains(file.getFileName().toString())) {
                        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                        NodeList nodeList;
                        try {
                            DocumentBuilder builder = factory.newDocumentBuilder();
                            Document document = builder.parse(file.toString());
                            document.getDocumentElement().normalize();
                             nodeList = document.getElementsByTagName("dependency");
                        } catch (ParserConfigurationException e) {
                            throw new RuntimeException(e);
                        } catch (SAXException e) {
                            throw new RuntimeException(e);
                        }

                        // Loop through each <dependency> element
                        for (int i = 1; i < nodeList.getLength(); i++) {
                            Element element = (Element) nodeList.item(i);

                            // Get the <artifactId> value
                            NodeList groupIdList = element.getElementsByTagName("groupId");
                            NodeList version = element.getElementsByTagName("version");

                            if (groupIdList.getLength() > 0) {
                                String groupId = groupIdList.item(0).getTextContent();
                                switch (groupId)  {
                                    case "org.apache.tiles" : {
                                        if (version.getLength() > 0 ) {
                                            String ver = version.item(0).getTextContent();
                                            String [] versplit = ver.split("\\.");
                                            if(isInteger(versplit[0])) {
                                                if (Integer.valueOf(versplit[0]) < 3) {
                                                    JavaCVEs cves = new JavaCVEs();
                                                    cves.setGroupId(groupId);
                                                    cves.setFilePath(file.toString());
                                                    cves.setCves("CVE-2023-50422");
                                                    cves.setVersion(ver);
                                                    javaCVEsList.add(cves);
                                                }
                                            }
                                        }

                                    }
                                    case "com.rabbitmq" : {
                                        if (version.getLength() > 0 ) {
                                            String ver = version.item(0).getTextContent();
                                            String [] versplit = ver.split("\\.");
                                            if(isInteger(versplit[0])) {
                                                if (Integer.valueOf(versplit[0]) < 3 && Integer.valueOf(versplit[1]) < 2) {
                                                    JavaCVEs cves = new JavaCVEs();
                                                    cves.setGroupId(groupId);
                                                    cves.setFilePath(file.toString());
                                                    cves.setCves("CVE-2023-49583");
                                                    cves.setVersion(ver);
                                                    javaCVEsList.add(cves);
                                                }
                                            }
                                        }

                                    }
                                }
                            }
                        }
//                        List<String> lines = Files.readAllLines(file);
//                        for (String line : lines) {
//                            if (line.contains("<groupId>rate-email</groupId>")) {
//                                JavaCVEs cvEs = new JavaCVEs();
//                                cvEs.setFilePath(file.toString());
//                                cvEs.setCves("CVE-2023-50422");
//                                cvEs.setGroupId(line.trim());
//                                javaCVEsList.add(cvEs);
//                            }
//                        }
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            e.printStackTrace();
        }

        return javaCVEsList;
    }
}
