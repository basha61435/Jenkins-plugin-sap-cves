/*
package io.jenkins.plugins;

import hudson.model.TaskListener;
import io.jenkins.plugins.cves.CVEsModel;
import io.jenkins.plugins.cves.FindFiles;
import org.junit.jupiter.api.Test;

import java.util.List;

class FindFilesTest {
    @Test
    void get() {
        FindFiles files = new FindFiles();
//        C:\\Users\\Basha\\IdeaProjects\\ro-ui-v3
//        C:\Users\Basha\IdeaProjects\ro-apps

        SimpleTaskListener listener = new SimpleTaskListener();
        List<CVEsModel> list =  files.getJavaCVEs("C:\\Users\\Basha\\IdeaProjects\\ro-apps");
//        List<CVEsModel> list1 =  files.getJavaCVEs("C:\\Users\\Basha\\IdeaProjects\\ro-ui-v3");
        System.out.println(list);
    }

    @Test
    void getVersion() {
        FindFiles files = new FindFiles();
        boolean bol = files.compare("14.1.2", "15.1.0");
        System.out.println("compare :"+bol);
    }

}
*/
