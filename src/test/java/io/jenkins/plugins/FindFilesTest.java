package io.jenkins.plugins;

import hudson.model.TaskListener;
import io.jenkins.plugins.cves.CVEsModel;
import io.jenkins.plugins.cves.FindFiles;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class FindFilesTest {
    @Test
    void get() throws IOException {
        FindFiles files = new FindFiles();
        TaskListener dummyListener = new DummyTaskListener();
//        List<CVEsModel> list =  files.getCVEs("C:\\Users\\Basha\\IdeaProjects\\ro-apps", dummyListener);
        List<CVEsModel> list1 =  files.getCVEs("C:\\Users\\Basha\\IdeaProjects\\ro-ui-v3", dummyListener);
        System.out.println(list1);
    }

    @Test
    void getVersion() {
        FindFiles files = new FindFiles();
        boolean bol = files.compare("14.1.2", "15.1.0");
        System.out.println("compare :"+bol);
    }
    @Test
    void pattern() {
        String format = "(\\w+\\.?)+";
        Pattern pattern = Pattern.compile(format);
        String codeVersion =  "\"\\^2.123.23\"/\"";
        Matcher matcher = pattern.matcher(codeVersion);
        if(matcher.find()) {
            System.out.println(matcher.group());
        }
    }

}
