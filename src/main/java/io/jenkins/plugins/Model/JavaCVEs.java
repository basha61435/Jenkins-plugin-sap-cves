package io.jenkins.plugins.Model;

import lombok.*;


@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class JavaCVEs {
    private String filePath;
    private String groupId;
    private String version;
    private String cves;

    @Override
    public String toString() {
        return "{" +
                "filePAth:'" + filePath + '\'' +
                ", groupId:'" + groupId + '\'' +
                ", version:'" + version + '\'' +
                ", cves:'" + cves + '\'' +
                '}';
    }
}
