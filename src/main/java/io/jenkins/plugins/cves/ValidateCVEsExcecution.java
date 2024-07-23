package io.jenkins.plugins.cves;

import hudson.FilePath;
import hudson.model.TaskListener;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.SynchronousNonBlockingStepExecution;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class ValidateCVEsExcecution extends SynchronousNonBlockingStepExecution<List<CVEsModel>> implements Serializable {

    private static final long serialVersionUID = 1L;
//    private transient SAPCVEs sapcvEs;

    protected ValidateCVEsExcecution(SAPCVEs sapcves, StepContext context) {
        super(context);
    }

    @Override
    protected List<CVEsModel> run() throws Exception {
        TaskListener listener = getContext().get(TaskListener.class);
        FilePath workspace = getContext().get(FilePath.class);
        String workspacePath = null;
        List<CVEsModel> javaCVEsList = new ArrayList<>();
        if(workspace != null) {
            workspacePath = workspace.getRemote();
            FindFiles findFiles = new FindFiles();
            javaCVEsList = findFiles.getJavaCVEs(workspacePath);
        }

        listener.getLogger().println("path: " + workspacePath);
        listener.getLogger().println("cves: " + javaCVEsList);
        return javaCVEsList;
    }

}
