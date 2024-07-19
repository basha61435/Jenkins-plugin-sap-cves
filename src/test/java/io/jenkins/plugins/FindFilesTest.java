package io.jenkins.plugins;

import io.jenkins.plugins.Model.JavaCVEs;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FindFilesTest {
    @Test
    void get() {
        FindFiles files = new FindFiles();
        List<JavaCVEs> list =  files.getJavaCVEs("C:\\Users\\Basha\\IdeaProjects\\ro-apps");
        System.out.println(list);
    }

}