package com.quizlet.upgrade.ui.fragment;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.core.widget.NestedScrollView;
import androidx.fragment.app.AbstractC1136h0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyTextButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class TermsAndConditionsModalFragment extends Hilt_TermsAndConditionsModalFragment {
    public static final String V;
    public com.quizlet.quizletandroid.ui.navigationmanagers.i I;
    public com.quizlet.assembly.databinding.b J;
    public final u K = kotlin.l.b(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 13));
    public final com.quizlet.uicommon.ui.common.dialogs.b L = com.quizlet.uicommon.ui.common.dialogs.b.a;
    public final boolean M = true;

    static {
        Intrinsics.checkNotNullExpressionValue("TermsAndConditionsModalFragment", "getSimpleName(...)");
        V = "TermsAndConditionsModalFragment";
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final void R(FrameLayout container, AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        com.quizlet.assembly.databinding.b bVar = this.J;
        if (bVar == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        container.addView((NestedScrollView) bVar.b);
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final com.quizlet.uicommon.ui.common.dialogs.b S() {
        return this.L;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment
    public final String W() {
        return (String) this.K.getValue();
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment
    public final boolean X() {
        return this.M;
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_terms_and_conditions, viewGroup, false);
        int i = R.id.termsAndConditionsText;
        if (((QTextView) AbstractC3375o2.c(R.id.termsAndConditionsText, viewInflate)) != null) {
            i = R.id.tosAndPpLink;
            AssemblyTextButton assemblyTextButton = (AssemblyTextButton) AbstractC3375o2.c(R.id.tosAndPpLink, viewInflate);
            if (assemblyTextButton != null) {
                this.J = new com.quizlet.assembly.databinding.b(4, assemblyTextButton, (NestedScrollView) viewInflate);
                return super.onCreateView(inflater, viewGroup, bundle);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment, com.quizlet.baseui.base.BaseDaggerDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        this.J = null;
        super.onDestroyView();
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        com.quizlet.assembly.databinding.b bVar = this.J;
        if (bVar == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        ((AssemblyTextButton) bVar.c).setOnClickListener(new com.quizlet.upgrade.ui.activity.c(this, 1));
    }
}
