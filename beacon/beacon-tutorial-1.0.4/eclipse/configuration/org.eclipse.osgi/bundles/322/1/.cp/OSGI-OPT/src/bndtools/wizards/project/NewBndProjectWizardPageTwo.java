/*******************************************************************************
 * Copyright (c) 2010 Neil Bartlett.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Neil Bartlett - initial API and implementation
 *******************************************************************************/
package bndtools.wizards.project;

import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationTargetException;

import org.bndtools.api.BndtoolsConstants;
import org.eclipse.core.resources.IFile;
import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.IProjectDescription;
import org.eclipse.core.resources.IWorkspaceRunnable;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.core.runtime.SubMonitor;
import org.eclipse.jdt.core.IJavaProject;
import org.eclipse.jdt.ui.wizards.NewJavaProjectWizardPageOne;
import org.eclipse.jdt.ui.wizards.NewJavaProjectWizardPageTwo;
import org.eclipse.jface.operation.IRunnableWithProgress;
import org.eclipse.jface.wizard.WizardPage;

import aQute.bnd.build.Project;
import bndtools.Plugin;

public class NewBndProjectWizardPageTwo extends NewJavaProjectWizardPageTwo {

    private final WizardPage previousPage;

    public NewBndProjectWizardPageTwo(WizardPage previousPage, NewJavaProjectWizardPageOne pageOne) {
        super(pageOne);
        this.previousPage = previousPage;
    }

    @Override
    public void setVisible(boolean visible) {
        super.setVisible(visible);
        if (!visible && getContainer().getCurrentPage() == previousPage) {
            removeProvisonalProject();
        }
    }

    @Override
    public void configureJavaProject(IProgressMonitor monitor) throws CoreException, InterruptedException {
        super.configureJavaProject(monitor);

        IProject project = getJavaProject().getProject();
        IProjectDescription desc = project.getDescription();
        String[] natures = desc.getNatureIds();
        for (String nature : natures) {
            if (BndtoolsConstants.NATURE_ID.equals(nature))
                return;
        }
        String[] newNatures = new String[natures.length + 1];
        System.arraycopy(natures, 0, newNatures, 0, natures.length);
        newNatures[natures.length] = BndtoolsConstants.NATURE_ID;
        desc.setNatureIds(newNatures);
        project.setDescription(desc, null);
    }

    void doSetProjectDesc(final IProject project, final IProjectDescription desc) throws CoreException {
        final IWorkspaceRunnable workspaceOp = new IWorkspaceRunnable() {
            public void run(IProgressMonitor monitor) throws CoreException {
                project.setDescription(desc, monitor);
            }
        };
        try {
            getContainer().run(true, true, new IRunnableWithProgress() {
                public void run(IProgressMonitor monitor) throws InvocationTargetException, InterruptedException {
                    try {
                        project.getWorkspace().run(workspaceOp, monitor);
                    } catch (CoreException e) {
                        throw new InvocationTargetException(e);
                    }
                }
            });
        } catch (InvocationTargetException e) {
            throw (CoreException) e.getTargetException();
        } catch (InterruptedException e) {
            throw new CoreException(new Status(IStatus.ERROR, Plugin.PLUGIN_ID, 0, "Interrupted while adding Bnd OSGi Project nature to project.", e));
        }
    }

    @Override
    protected void initializeBuildPath(final IJavaProject javaProject, IProgressMonitor monitor) throws CoreException {
        IWorkspaceRunnable wsop = new IWorkspaceRunnable() {
            public void run(IProgressMonitor monitor) throws CoreException {
                IFile bndFile = javaProject.getProject().getFile(Project.BNDFILE);
                if (!bndFile.exists())
                    bndFile.create(new ByteArrayInputStream(new byte[0]), false, monitor);
                monitor.done();
            }
        };

        SubMonitor progress = SubMonitor.convert(monitor, 5);
        javaProject.getProject().getWorkspace().run(wsop, progress.newChild(1));
        super.initializeBuildPath(javaProject, progress.newChild(4));
    }

}