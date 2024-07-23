package io.jenkins.plugins.cves;

import lombok.*;


@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CVEsModel {
    private String filePath;
    private String library;
    private String version;
    private String cves;
    private String url;

    @Override
    public String toString() {
        return "{" +
                "filePath='" + filePath + '\'' +
                ", library='" + library + '\'' +
                ", version='" + version + '\'' +
                ", cves='" + cves + '\'' +
                ", url='" + url + '\'' +
                '}';
    }
}
