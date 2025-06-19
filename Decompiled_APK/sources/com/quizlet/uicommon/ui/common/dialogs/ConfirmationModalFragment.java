package com.quizlet.uicommon.ui.common.dialogs;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Guideline;
import androidx.fragment.app.AbstractC1136h0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblySecondaryButton;
import com.quizlet.explanations.databinding.n;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class ConfirmationModalFragment extends UnstyledConvertibleModalDialogFragment {
    public n E;
    public Function0 F;
    public com.quizlet.quizletandroid.ui.studymodes.assistant.d G;

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final void R(FrameLayout container, AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        container.addView((ConstraintLayout) c0().c);
    }

    public final n c0() {
        n nVar = this.E;
        if (nVar != null) {
            return nVar;
        }
        throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_confirmation_modal, viewGroup, false);
        int i = R.id.actionButton;
        AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.actionButton, viewInflate);
        if (assemblyPrimaryButton != null) {
            i = R.id.cancelButton;
            AssemblySecondaryButton assemblySecondaryButton = (AssemblySecondaryButton) AbstractC3375o2.c(R.id.cancelButton, viewInflate);
            if (assemblySecondaryButton != null) {
                i = R.id.dialog_description_text;
                QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.dialog_description_text, viewInflate);
                if (qTextView != null) {
                    i = R.id.dialog_title_text;
                    QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.dialog_title_text, viewInflate);
                    if (qTextView2 != null) {
                        i = R.id.drawer_handler_view;
                        View viewC = AbstractC3375o2.c(R.id.drawer_handler_view, viewInflate);
                        if (viewC != null) {
                            i = R.id.guideline_end;
                            if (((Guideline) AbstractC3375o2.c(R.id.guideline_end, viewInflate)) != null) {
                                i = R.id.guideline_start;
                                if (((Guideline) AbstractC3375o2.c(R.id.guideline_start, viewInflate)) != null) {
                                    this.E = new n((ConstraintLayout) viewInflate, assemblyPrimaryButton, assemblySecondaryButton, qTextView, qTextView2, viewC);
                                    return super.onCreateView(inflater, viewGroup, bundle);
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment, com.quizlet.baseui.base.BaseViewBindingDialogFragment, com.quizlet.baseui.base.BaseDaggerDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        super.onDestroyView();
        this.E = null;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        n nVarC0 = c0();
        String string = requireArguments().getString("ARG_TITLE");
        if (string == null) {
            throw new IllegalStateException("Missing required argument (Title)");
        }
        ((QTextView) nVarC0.e).setText(string);
        n nVarC02 = c0();
        String string2 = requireArguments().getString("ARG_DESCRIPTION");
        if (string2 == null) {
            throw new IllegalStateException("Missing required argument (Description)");
        }
        ((QTextView) nVarC02.d).setText(string2);
        n nVarC03 = c0();
        String string3 = requireArguments().getString("ARG_ACTION_TEXT");
        if (string3 == null) {
            throw new IllegalStateException("Missing required argument (Action Text)");
        }
        ((AssemblyPrimaryButton) nVarC03.f).setText(string3);
        n nVarC04 = c0();
        String string4 = requireArguments().getString("ARG_CANCEL_TEXT");
        if (string4 == null) {
            throw new IllegalStateException("Missing required argument (Cancel Text)");
        }
        ((AssemblySecondaryButton) nVarC04.g).setText(string4);
        final int i = 0;
        ((AssemblyPrimaryButton) c0().f).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.uicommon.ui.common.dialogs.c
            public final /* synthetic */ ConfirmationModalFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i) {
                    case 0:
                        ConfirmationModalFragment confirmationModalFragment = this.b;
                        Function0 function0 = confirmationModalFragment.F;
                        if (function0 != null) {
                            function0.invoke();
                        }
                        confirmationModalFragment.H(false, false);
                        break;
                    default:
                        ConfirmationModalFragment confirmationModalFragment2 = this.b;
                        com.quizlet.quizletandroid.ui.studymodes.assistant.d dVar = confirmationModalFragment2.G;
                        if (dVar != null) {
                            dVar.invoke();
                        }
                        confirmationModalFragment2.H(false, false);
                        break;
                }
            }
        });
        final int i2 = 1;
        ((AssemblySecondaryButton) c0().g).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.uicommon.ui.common.dialogs.c
            public final /* synthetic */ ConfirmationModalFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i2) {
                    case 0:
                        ConfirmationModalFragment confirmationModalFragment = this.b;
                        Function0 function0 = confirmationModalFragment.F;
                        if (function0 != null) {
                            function0.invoke();
                        }
                        confirmationModalFragment.H(false, false);
                        break;
                    default:
                        ConfirmationModalFragment confirmationModalFragment2 = this.b;
                        com.quizlet.quizletandroid.ui.studymodes.assistant.d dVar = confirmationModalFragment2.G;
                        if (dVar != null) {
                            dVar.invoke();
                        }
                        confirmationModalFragment2.H(false, false);
                        break;
                }
            }
        });
        View drawerHandlerView = c0().b;
        Intrinsics.checkNotNullExpressionValue(drawerHandlerView, "drawerHandlerView");
        boolean zX = X();
        Intrinsics.checkNotNullParameter(drawerHandlerView, "<this>");
        drawerHandlerView.setVisibility(!zX ? 8 : 0);
    }
}
