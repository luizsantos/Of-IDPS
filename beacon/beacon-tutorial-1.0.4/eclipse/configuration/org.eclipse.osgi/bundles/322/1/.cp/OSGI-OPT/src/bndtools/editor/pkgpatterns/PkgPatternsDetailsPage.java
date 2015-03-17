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
package bndtools.editor.pkgpatterns;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.eclipse.jface.bindings.keys.KeyStroke;
import org.eclipse.jface.bindings.keys.ParseException;
import org.eclipse.jface.fieldassist.ContentProposalAdapter;
import org.eclipse.jface.fieldassist.ControlDecoration;
import org.eclipse.jface.fieldassist.FieldDecoration;
import org.eclipse.jface.fieldassist.FieldDecorationRegistry;
import org.eclipse.jface.fieldassist.IContentProposal;
import org.eclipse.jface.fieldassist.IContentProposalListener;
import org.eclipse.jface.fieldassist.TextContentAdapter;
import org.eclipse.jface.viewers.ISelection;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Text;
import org.eclipse.ui.forms.AbstractFormPart;
import org.eclipse.ui.forms.IDetailsPage;
import org.eclipse.ui.forms.IFormPart;
import org.eclipse.ui.forms.IManagedForm;
import org.eclipse.ui.forms.widgets.FormToolkit;
import org.eclipse.ui.forms.widgets.Section;

import aQute.bnd.build.model.BndEditModel;
import aQute.bnd.build.model.clauses.HeaderClause;
import aQute.bnd.osgi.Constants;
import bndtools.UIConstants;
import bndtools.javamodel.FormPartJavaSearchContext;
import bndtools.utils.ModificationLock;

public class PkgPatternsDetailsPage<C extends HeaderClause> extends AbstractFormPart implements IDetailsPage, PropertyChangeListener {

    private PkgPatternsListPart<C> listPart;
    private final ModificationLock modifyLock = new ModificationLock();
    protected List<C> selectedClauses = Collections.emptyList();

    private BndEditModel model;

    private Composite mainComposite;
    private Text txtName;
    private Text txtVersion;

    private final String title;

    public PkgPatternsDetailsPage(String title) {
        this.title = title;
    }

    public void createContents(Composite parent) {
        FormToolkit toolkit = getManagedForm().getToolkit();

        FieldDecoration assistDecor = FieldDecorationRegistry.getDefault().getFieldDecoration(FieldDecorationRegistry.DEC_CONTENT_PROPOSAL);
        KeyStroke assistKeyStroke = null;
        try {
            assistKeyStroke = KeyStroke.getInstance("Ctrl+Space");
        } catch (ParseException x) {
            // Ignore
        }

        Section mainSection = toolkit.createSection(parent, Section.TITLE_BAR);
        mainSection.setText(title);

        mainComposite = toolkit.createComposite(mainSection);
        mainSection.setClient(mainComposite);

        toolkit.createLabel(mainComposite, "Pattern:");
        txtName = toolkit.createText(mainComposite, "", SWT.BORDER);
        ControlDecoration decPattern = new ControlDecoration(txtName, SWT.LEFT | SWT.TOP, mainComposite);
        decPattern.setImage(assistDecor.getImage());
        decPattern.setDescriptionText(MessageFormat.format("Content assist is available. Press {0} or start typing to activate", assistKeyStroke.format()));
        decPattern.setShowHover(true);
        decPattern.setShowOnlyOnFocus(true);

        PkgPatternsProposalProvider proposalProvider = new PkgPatternsProposalProvider(new FormPartJavaSearchContext(this));
        ContentProposalAdapter patternProposalAdapter = new ContentProposalAdapter(txtName, new TextContentAdapter(), proposalProvider, assistKeyStroke, UIConstants.autoActivationCharacters());
        patternProposalAdapter.addContentProposalListener(proposalProvider);
        patternProposalAdapter.setProposalAcceptanceStyle(ContentProposalAdapter.PROPOSAL_IGNORE);
        patternProposalAdapter.setAutoActivationDelay(1000);
        patternProposalAdapter.setLabelProvider(new PkgPatternProposalLabelProvider());
        patternProposalAdapter.addContentProposalListener(new IContentProposalListener() {
            public void proposalAccepted(IContentProposal proposal) {
                PkgPatternProposal patternProposal = (PkgPatternProposal) proposal;
                String toInsert = patternProposal.getContent();
                int currentPos = txtName.getCaretPosition();
                txtName.setSelection(patternProposal.getReplaceFromPos(), currentPos);
                txtName.insert(toInsert);
                txtName.setSelection(patternProposal.getCursorPosition());
            }
        });

        toolkit.createLabel(mainComposite, "Version:");
        txtVersion = toolkit.createText(mainComposite, "", SWT.BORDER);

        /*
         * Section attribsSection = toolkit.createSection(parent, Section.TITLE_BAR | Section.TWISTIE);
         * attribsSection.setText("Extra Attributes"); Composite attribsComposite =
         * toolkit.createComposite(attribsSection);
         */

        // Listeners
        txtName.addModifyListener(new ModifyListener() {
            public void modifyText(ModifyEvent e) {
                if (!modifyLock.isUnderModification()) {
                    if (selectedClauses.size() == 1) {
                        selectedClauses.get(0).setName(txtName.getText());
                        if (listPart != null) {
                            listPart.updateLabels(selectedClauses);
                            listPart.validate();
                        }
                        markDirty();
                    }
                }
            }
        });
        txtVersion.addModifyListener(new ModifyListener() {
            public void modifyText(ModifyEvent e) {
                if (!modifyLock.isUnderModification()) {
                    String text = txtVersion.getText();
                    if (text.length() == 0)
                        text = null;

                    for (HeaderClause clause : selectedClauses) {
                        clause.getAttribs().put(Constants.VERSION_ATTRIBUTE, text);
                    }
                    if (listPart != null) {
                        listPart.updateLabels(selectedClauses);
                        listPart.validate();
                    }
                    markDirty();
                }
            }
        });

        // Layout
        GridData gd;

        parent.setLayout(new GridLayout());
        mainSection.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false));
        mainComposite.setLayout(new GridLayout(2, false));

        gd = new GridData(SWT.FILL, SWT.TOP, true, false);
        gd.horizontalIndent = 5;
        gd.widthHint = 100;
        txtName.setLayoutData(gd);

        gd = new GridData(SWT.FILL, SWT.TOP, true, false);
        gd.horizontalIndent = 5;
        gd.widthHint = 100;
        txtVersion.setLayoutData(gd);
    }

    protected final Composite getMainComposite() {
        return mainComposite;
    }

    public void selectionChanged(IFormPart part, ISelection selection) {
        @SuppressWarnings("unchecked")
        List<C> tmp = ((IStructuredSelection) selection).toList();
        selectedClauses = new ArrayList<C>(tmp);

        refresh();

        if (txtName.isEnabled()) {
            txtName.setFocus();
            txtName.setSelection(selectedClauses.get(0).getName().length());
        }
    }

    @Override
    public void initialize(IManagedForm form) {
        super.initialize(form);

        this.model = (BndEditModel) form.getInput();
        this.model.addPropertyChangeListener(Constants.IMPORT_PACKAGE, this);
    }

    @Override
    public void dispose() {
        super.dispose();
        this.model.removePropertyChangeListener(Constants.IMPORT_PACKAGE, this);
    }

    @Override
    public void refresh() {
        super.refresh();
        modifyLock.modifyOperation(new Runnable() {
            public void run() {
                if (selectedClauses.isEmpty()) {
                    txtName.setEnabled(false);
                    txtVersion.setEnabled(false);
                    txtVersion.setMessage("Empty Selection");
                } else if (selectedClauses.size() == 1) {
                    txtName.setEnabled(true);
                    txtName.setText(selectedClauses.get(0).getName());

                    String version = selectedClauses.get(0).getAttribs().get(Constants.VERSION_ATTRIBUTE);
                    txtVersion.setEnabled(true);
                    txtVersion.setMessage("");
                    txtVersion.setText(version != null ? version : "");
                } else {
                    txtName.setEnabled(false);

                    String firstVersion = selectedClauses.get(0).getAttribs().get(Constants.VERSION_ATTRIBUTE);
                    boolean versionsDiffer = false;
                    for (C selectedClause : selectedClauses) {
                        String anotherVersion = selectedClause.getAttribs().get(Constants.VERSION_ATTRIBUTE);
                        if (firstVersion != null && !firstVersion.equals(anotherVersion)) {
                            versionsDiffer = true;
                            break;
                        }
                    }
                    if (versionsDiffer) {
                        txtVersion.setEnabled(true);
                        txtVersion.setText("");
                        txtVersion.setMessage("Multiple values; type to override all");
                    } else {
                        txtVersion.setEnabled(true);
                        txtVersion.setMessage("");
                        txtVersion.setText(firstVersion != null ? firstVersion : "");
                    }
                }
            }
        });
    }

    @Override
    public void commit(boolean onSave) {
        super.commit(onSave);
        if (listPart != null)
            listPart.commit(onSave);
    }

    public void propertyChange(PropertyChangeEvent evt) {
        // Object container = getManagedForm().getContainer();
    }

    public void setListPart(PkgPatternsListPart<C> listPart) {
        this.listPart = listPart;
    }

    protected PkgPatternsListPart<C> getListPart() {
        return listPart;
    }
}
