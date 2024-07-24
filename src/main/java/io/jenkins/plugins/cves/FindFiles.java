package io.jenkins.plugins.cves;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.model.TaskListener;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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

public class FindFiles {
    String url = "https://www.cve.org/CVERecord?id=%s";

    public List<CVEsModel> getJavaCVEs(String path, TaskListener listener) throws IOException {
        List<CVEsModel> cvesList = new ArrayList<>();
        Path startDir = Paths.get(path);
        List<String> targetFiles = Arrays.asList("pom.xml", "package.json");
        ObjectMapper mapper = new ObjectMapper();
        List<CVEsModel> javaCVEsList = readJsonFile("JavaCVEsJson.json", mapper);
        listener.getLogger().println("test cves list for java :" + javaCVEsList);
        List<CVEsModel> nodeCVEsList = readJsonFile("NodeCVEsJson.json", mapper);
        listener.getLogger().println("test cves list for node :" + nodeCVEsList);
        try {
            Files.walkFileTree(startDir, new SimpleFileVisitor<Path>() {

                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    if (dir.getFileName().toString().equals("node_modules") || dir.getFileName().toString().equals(".git") || dir.getFileName().toString().equals(".idea")) {
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

                        for (int i = 1; i < nodeList.getLength(); i++) {
                            Element element = (Element) nodeList.item(i);
                            NodeList groupIdList = element.getElementsByTagName("groupId");
                            NodeList version = element.getElementsByTagName("version");
                            if (groupIdList.getLength() > 0) {
                                String groupId = groupIdList.item(0).getTextContent();
                                // TODO : For local testing to read cves json file
                             /*     String currentDirectory = System.getProperty("user.dir");
                                String jsonfilePath = String.format("%s/src/main/resources/JavaCVEsJson.json", getPluginDirectoryPath());
                                listener.getLogger().println("jsonfilePath :" + jsonfilePath);
                                List<CVEsModel> nodeCVEsList = mapper.readValue(
                                        new File(jsonfilePath),
                                        mapper.getTypeFactory().constructCollectionType(List.class, CVEsModel.class)
                                ); */

                                for (CVEsModel cves : javaCVEsList) {
                                    if (groupId.equalsIgnoreCase(cves.getLibrary())) {
                                        if (version.getLength() > 0) {
                                            String codeVersion = version.item(0).getTextContent();
                                            if (compare(codeVersion, cves.getVersion())) {
                                                cves.setFilePath(file.toString());
                                                cves.setVersion(codeVersion);
                                                cves.setUrl(String.format(url, cves.getCves()));
                                                cvesList.add(cves);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (file != null && targetFiles.get(1).contains(file.getFileName().toString())) {
                        // TODO : For local testing to read cves json file
                       /* String currentDirectory = System.getProperty("user.dir");
                       String jsonfilePath = String.format("%s\\src\\main\\resources\\NodeCVEsJson.json", getPluginDirectoryPath());
                       List<CVEsModel> node2 = mapper.readValue(
                                new File(jsonfilePath),
                                mapper.getTypeFactory().constructCollectionType(List.class, CVEsModel.class)
                        );  */

                        JsonNode node = mapper.readValue(new File(file.toString()), JsonNode.class);
                        if (node.has("dependencies")) {
                            JsonNode no = node.get("dependencies");
                            for (CVEsModel cves : nodeCVEsList) {
                                if (no.has(cves.getLibrary())) {
                                    String codeVersion = no.get(cves.getLibrary()).toString();
                                    String pattern = "\\d+\\.\\d+\\.\\d+";
                                    Pattern regex = Pattern.compile(pattern);
                                    Matcher matcher = regex.matcher(codeVersion);
                                    if (matcher.find()) {
                                        codeVersion = matcher.group();
                                    }
                                    if (compare(codeVersion, cves.getVersion())) {
                                        cves.setFilePath(file.toString());
                                        cves.setVersion(codeVersion);
                                        cves.setUrl(String.format(url, cves.getCves()));
                                        cvesList.add(cves);
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

        return cvesList;
    }

    public boolean compare(String codeVer, String cveVersion) {
        String[] codeSplit = codeVer.split("\\.");
        String[] cveSplit = cveVersion.split("\\.");
        if (!isInteger(codeSplit[0])) {
            return false;
        }
        if (Integer.parseInt(codeSplit[0]) == Integer.parseInt(cveSplit[0])) {
            return Integer.parseInt(codeSplit[1]) < Integer.parseInt(cveSplit[1]);

        } else return Integer.parseInt(codeSplit[0]) < Integer.parseInt(cveSplit[0]);
    }

    private List<CVEsModel> readJsonFile(String fileName, ObjectMapper mapper) throws IOException {
        // Use getClass().getResourceAsStream() to get the file from the classpath
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(fileName);
        if (inputStream == null) {
            throw new IOException("Resource not found: " + fileName);
        }
        // Convert InputStream to String
        String jsonContent = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        List<CVEsModel> cvesList = mapper.readValue(jsonContent, new TypeReference<List<CVEsModel>>() {
        });
        return cvesList;
    }

    /*private static boolean isInteger(String str) {
        if (str == null) {
            return false;
        }
        try {
            Integer.parseInt(str);
        } catch (NumberFormatException nfe) {
            return false;
        }
        return true;
    }*/
}
