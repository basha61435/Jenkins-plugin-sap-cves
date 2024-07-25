package io.jenkins.plugins.cves;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.model.TaskListener;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
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
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FindFiles {
    String url = "https://www.cve.org/CVERecord?id=%s";
    String format = "(\\w+\\.?)+";
    Pattern pattern = Pattern.compile(format);

    public List<CVEsModel> getCVEs(String path, TaskListener listener) throws IOException {
        List<CVEsModel> cvesList = new ArrayList<>();
        Path startDir = Paths.get(path);
        List<String> targetFiles = Arrays.asList("pom.xml", "package.json");
        ObjectMapper mapper = new ObjectMapper();
        // TODO : getting  SAP CVEs json in Jenkins plugin
        List<CVEsModel> javaCVEsList = readJsonFile("JavaCVEsJson.json", mapper);
        listener.getLogger().println("test cves list for java :" + javaCVEsList);
        List<CVEsModel> nodeCVEsList = readJsonFile("NodeCVEsJson.json", mapper);
        listener.getLogger().println("test cves list for node :" + nodeCVEsList);


        // TODO : getting  SAP CVEs json in local
        /*String currentDirectory = System.getProperty("user.dir");
        String javaJsonfilePath = String.format("%s/src/main/resources/JavaCVEsJson.json", currentDirectory);
        List<CVEsModel> javaCVEsList = mapper.readValue(
                new File(javaJsonfilePath),
                mapper.getTypeFactory().constructCollectionType(List.class, CVEsModel.class)
        );
        String nodeJsonfilePath = String.format("%s\\src\\main\\resources\\NodeCVEsJson.json", currentDirectory);
        List<CVEsModel> nodeCVEsList = mapper.readValue(
                new File(nodeJsonfilePath),
                mapper.getTypeFactory().constructCollectionType(List.class, CVEsModel.class)
        );*/

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

                    if (file != null && targetFiles.contains(file.getFileName().toString())) {
                        if (file.getFileName().toString().equals("pom.xml")) {
                            prepareJavaCVEs(file, cvesList, javaCVEsList);
                        } else if (file.getFileName().toString().equals("package.json")) {
                            prepareNodeCVEs(file, cvesList, nodeCVEsList, mapper);
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            listener.getLogger().println("Error traversing files: " + e.getMessage());
        }

        return cvesList;
    }

    private void prepareJavaCVEs(Path file, List<CVEsModel> cvesList, List<CVEsModel> javaCVEsList) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        NodeList nodeList;
        NodeList nodePropertiesList;
        try {
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(file.toString());
            document.getDocumentElement().normalize();
            nodeList = document.getElementsByTagName("dependency");
            nodePropertiesList = document.getElementsByTagName("properties");
        } catch (ParserConfigurationException | IOException e) {
            throw new RuntimeException(e);
        } catch (SAXException e) {
            throw new RuntimeException(e);
        }
        Map<String, String> propertiesMap = new HashMap<>();
        for (int j = 0; j < nodePropertiesList.getLength(); j++) {
            Element propertiesElement = (Element) nodePropertiesList.item(j);
            NodeList propertiesChildren = propertiesElement.getChildNodes();

            for (int k = 0; k < propertiesChildren.getLength(); k++) {
                Node node = propertiesChildren.item(k);
                if (node instanceof Element) {
                    propertiesMap.put(node.getNodeName(), node.getTextContent());
                }
            }
        }
        for (int i = 1; i < nodeList.getLength(); i++) {
            Element element = (Element) nodeList.item(i);
            NodeList groupIdList = element.getElementsByTagName("groupId");
            NodeList versionList = element.getElementsByTagName("version");

            if (groupIdList.getLength() > 0) {
                String groupId = groupIdList.item(0).getTextContent();
                for (CVEsModel javacves : javaCVEsList) {
                    if (groupId.equalsIgnoreCase(javacves.getLibrary())) {
                        if (versionList.getLength() > 0) {
                            String version = versionList.item(0).getTextContent();
                            String codeVersion = getSourceCodeLibraryVersion(version);
                            if( !isInteger(codeVersion.split("\\.")[0])) {
                                codeVersion = propertiesMap.get(codeVersion);
                            }
                            CVEsModel cves;
                            if (compare(codeVersion, javacves.getVersion())) {
                                try {
                                    cves = (CVEsModel) javacves.clone();
                                } catch (CloneNotSupportedException e) {
                                    throw new RuntimeException(e);
                                }
                                cves.setFilePath(file.toString());
                                cves.setVersion(codeVersion);
                                cves.setUrl(String.format(url, javacves.getCves()));
                                cvesList.add(cves);
                            }
                        }
                    }
                }
            }
        }
    }

    private void prepareNodeCVEs(Path file, List<CVEsModel> cvesList, List<CVEsModel> nodeCVEsList, ObjectMapper mapper) throws IOException {
        JsonNode node = mapper.readValue(new File(file.toString()), JsonNode.class);
        if (node.has("dependencies")) {
            JsonNode no = node.get("dependencies");
            for (CVEsModel nodeCVEs : nodeCVEsList) {
                if (no.has(nodeCVEs.getLibrary())) {
                    String codeVersion = getSourceCodeLibraryVersion(no.get(nodeCVEs.getLibrary()).toString());
                    if (compare(codeVersion, nodeCVEs.getVersion())) {
                        CVEsModel cves;
                        try {
                            cves = (CVEsModel) nodeCVEs.clone();
                        } catch (CloneNotSupportedException e) {
                            throw new RuntimeException(e);
                        }
                        cves.setFilePath(file.toString());
                        cves.setVersion(codeVersion);
                        cves.setUrl(String.format(url, nodeCVEs.getCves()));
                        cvesList.add(cves);
                    }
                }
            }
        }
    }

    public boolean compare(String codeVer, String cveVersion) {
        String[] codeSplit = codeVer.split("\\.");
        String[] cveSplit = cveVersion.split("\\.");

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

    private String getSourceCodeLibraryVersion(String libraryVersion) {
        Matcher matcher = pattern.matcher(libraryVersion);
        String version = null;
        if (matcher.find()) {
            version = matcher.group();
        }
        return version;
    }

    private static boolean isInteger(String str) {
        if (str == null) {
            return false;
        }
        try {
            Integer.parseInt(str);
        } catch (NumberFormatException nfe) {
            return false;
        }
        return true;
    }

}
