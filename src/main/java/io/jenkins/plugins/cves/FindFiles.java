package io.jenkins.plugins.cves;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.codehaus.groovy.runtime.StringGroovyMethods.isInteger;

//import static org.codehaus.groovy.runtime.StringGroovyMethods.isInteger;

public class FindFiles {
    String url = "https://www.cve.org/CVERecord?id=%s";

    public List<CVEsModel> getJavaCVEs(String path) {
        List<CVEsModel> javaCVEsList = new ArrayList<>();
        Path startDir = Paths.get(path);
        List<String> targetFiles = Arrays.asList("pom.xml", "package.json");
        try {
            Files.walkFileTree(startDir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    if (dir.getFileName().toString().equals("node_modules")) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {

                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                    if (file != null && targetFiles.get(0).contains(file.getFileName().toString())) {
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
                              /*  switch (groupId)  {
                                    case "org.apache.tiles" : {
                                        if (version.getLength() > 0 ) {
                                            String ver = version.item(0).getTextContent();
                                            String [] codeVersionSplit = ver.split("\\.");
                                            if(isInteger(codeVersionSplit[0])) {
                                                if (Integer.parseInt(codeVersionSplit[0]) < 3) {
//                                                    prepareCVEs(file.toString(), ver, javaCVEsList);
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
                                            String [] codeVersionSplit = ver.split("\\.");
                                            if(isInteger(codeVersionSplit[0])) {
                                                if (Integer.parseInt(codeVersionSplit[0]) < 3 && Integer.parseInt(codeVersionSplit[1]) < 2) {
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
                                }*/
                                ObjectMapper mapper = new ObjectMapper();
                                String currentDirectory = System.getProperty("user.dir");
                                String jsonfilePath = String.format("%s\\src\\main\\java\\io\\jenkins\\plugins\\json\\JavaCVEsJson.json", currentDirectory);
                                List<CVEsModel> node = mapper.readValue(
                                        new File(jsonfilePath),
                                        mapper.getTypeFactory().constructCollectionType(List.class, CVEsModel.class)
                                );
                                for(CVEsModel cves : node ) {
                                    if(groupId.equalsIgnoreCase(cves.getLibrary())) {
                                        if (version.getLength() > 0 ) {
                                            String codeVersion = version.item(0).getTextContent();
                                            if(compare(codeVersion, cves.getVersion())) {
//                                                    prepareCVEs(file.toString(), ver, javaCVEsList);
//                                                    JavaCVEs cves = new JavaCVEs();
//                                                    cves.setGroupId(groupId);
                                                    cves.setFilePath(file.toString());
//                                                    cves.setCves("CVE-2023-50422");
                                                    cves.setVersion(codeVersion);
                                                    cves.setUrl(String.format(url, cves.getCves()));
                                                    javaCVEsList.add(cves);
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
                    if (file != null && targetFiles.get(1).contains(file.getFileName().toString())) {
                        ObjectMapper mapper = new ObjectMapper();
                        String currentDirectory = System.getProperty("user.dir");
                        String jsonfilePath = String.format("%s\\src\\main\\java\\io\\jenkins\\plugins\\json\\NodeCVEsJson.json", currentDirectory);
                        List<CVEsModel> node1 = mapper.readValue(
                                new File(jsonfilePath),
                                mapper.getTypeFactory().constructCollectionType(List.class, CVEsModel.class)
                        );
                        JsonNode node = mapper.readValue(new File(file.toString()), JsonNode.class);
                        if( node.has("dependencies")) {
                            JsonNode no = node.get("dependencies");
                            for (CVEsModel cves : node1) {
                                if (no.has(cves.getLibrary())) {
                                    String codeVersion = no.get(cves.getLibrary()).toString();
                                    String pattern = "\\d+\\.\\d+\\.\\d+";
                                    Pattern regex = Pattern.compile(pattern);
                                    Matcher matcher = regex.matcher(codeVersion);
                                    if(matcher.find()) {
                                        codeVersion = matcher.group();
                                    }
                                    if (compare(codeVersion, cves.getVersion())) {
                                        cves.setFilePath(file.toString());
//                                      cves.setCves("CVE-2023-50422");
                                        cves.setVersion(codeVersion);
                                        cves.setUrl(String.format(url, cves.getCves()));
                                        javaCVEsList.add(cves);
                                    }
                                }
                            }
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            e.printStackTrace();
        }

        return javaCVEsList;
    }

    public boolean compare(String codeVer, String cveVersion) {
        String[] codeSplit = codeVer.split("\\.");
        String[] cveSplit = cveVersion.split("\\.");
        if(!isInteger(codeSplit[0])) {
            return false;
        }
        if (Integer.parseInt(codeSplit[0]) == Integer.parseInt(cveSplit[0])) {
            return Integer.parseInt(codeSplit[1]) < Integer.parseInt(cveSplit[1]);

        } else return Integer.parseInt(codeSplit[0]) < Integer.parseInt(cveSplit[0]);
    }
//    private void prepareCVEs(String filename, String version,)

//    private static boolean isInteger(String str) {
//        if (str == null) {
//            return false;
//        }
//        try {
//            Integer.parseInt(str);
//        } catch (NumberFormatException nfe) {
//            return false;
//        }
//        return true;
//    }
}
