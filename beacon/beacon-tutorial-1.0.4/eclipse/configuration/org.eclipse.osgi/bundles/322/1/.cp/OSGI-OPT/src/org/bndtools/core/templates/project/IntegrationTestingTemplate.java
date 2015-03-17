package org.bndtools.core.templates.project;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bndtools.api.IBndProject;
import org.bndtools.api.IProjectTemplate;
import org.osgi.framework.Constants;

import aQute.bnd.build.model.BndEditModel;
import aQute.bnd.build.model.EE;
import aQute.bnd.build.model.clauses.ExportedPackage;
import aQute.bnd.build.model.clauses.VersionedClause;
import aQute.bnd.header.Attrs;

public class IntegrationTestingTemplate implements IProjectTemplate {

    private static final String ALL_TEST_CASES_MACRO = "${classes;CONCRETE;EXTENDS;junit.framework.TestCase}"; //$NON-NLS-1$

    public void modifyInitialBndModel(BndEditModel model) {
        List<VersionedClause> newBuildPath = new ArrayList<VersionedClause>();

        List<VersionedClause> oldBuildPath = model.getBuildPath();
        if (oldBuildPath != null)
            newBuildPath.addAll(oldBuildPath);

        newBuildPath.add(createBundleRef("osgi.core", "[4.2,5)"));
        newBuildPath.add(createBundleRef("osgi.cmpn", null));
        newBuildPath.add(createBundleRef("junit.osgi", null));
        newBuildPath.add(createBundleRef("org.mockito.mockito-all", null));
        model.setBuildPath(newBuildPath);

        model.setTestSuites(Arrays.asList(ALL_TEST_CASES_MACRO));
        model.setRunFw("org.apache.felix.framework");
        model.setEE(EE.JavaSE_1_6);
        model.setPrivatePackages(Arrays.asList(new String[] {
            "org.example.tests"
        }));
        model.setRunBundles(Arrays.asList(new VersionedClause[] {
            createBundleRef("org.mockito.mockito-all", null)
        }));

        model.setSystemPackages(Arrays.asList(new ExportedPackage[] {
            new ExportedPackage("sun.reflect", new Attrs())
        }));
        model.setRunVMArgs("-ea");
    }

    static VersionedClause createBundleRef(String bsn, String version) {
        Attrs attribs = new Attrs();
        if (version != null)
            attribs.put(Constants.VERSION_ATTRIBUTE, version);
        return new VersionedClause(bsn, attribs);
    }

    public void modifyInitialBndProject(IBndProject project) {
        project.addResource("src/org/example/tests/ExampleTest.java", IntegrationTestingTemplate.class.getResource("ExampleTest.java.txt"));
    }

    public boolean enableTestSourceFolder() {
        return false;
    }
}
