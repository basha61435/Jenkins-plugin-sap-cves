package io.jenkins.plugins.Model;

import lombok.*;


@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class JavaCVEs {
    private String filePAth;
    private String groupId;
    private String version;
    private String cves;
}
