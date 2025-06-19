package com.quizlet.explanations.feedback.ui.fragments;

import android.os.Bundle;
import android.view.Window;
import android.widget.FrameLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import com.quizlet.explanations.feedback.data.ExplanationsFeedbackSetUpState;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class ExplanationsFeedbackModalFragment extends Hilt_ExplanationsFeedbackModalFragment {
    public static final String L;
    public final boolean J = true;
    public final boolean K = true;

    static {
        Intrinsics.checkNotNullExpressionValue("ExplanationsFeedbackModalFragment", "getSimpleName(...)");
        L = "ExplanationsFeedbackModalFragment";
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final void R(FrameLayout container, AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        String str = ExplanationsFeedbackFragment.l;
        Fragment fragmentE = fragmentManager.E(str);
        ExplanationsFeedbackFragment explanationsFeedbackFragment = fragmentE instanceof ExplanationsFeedbackFragment ? (ExplanationsFeedbackFragment) fragmentE : null;
        if (explanationsFeedbackFragment == null) {
            ExplanationsFeedbackSetUpState setUpState = (ExplanationsFeedbackSetUpState) requireArguments().getParcelable("ARG_SET_UP_STATE");
            if (setUpState == null) {
                throw new IllegalStateException("Missing required argument (ExplanationsFeedbackSetUpState)");
            }
            Intrinsics.checkNotNullParameter(setUpState, "setUpState");
            ExplanationsFeedbackFragment explanationsFeedbackFragment2 = new ExplanationsFeedbackFragment();
            Bundle bundle = new Bundle();
            bundle.putParcelable("ARG_SET_UP_STATE", setUpState);
            explanationsFeedbackFragment2.setArguments(bundle);
            C1121a c1121a = new C1121a(fragmentManager);
            c1121a.l(R.id.contentFragment, explanationsFeedbackFragment2, str);
            c1121a.g();
            explanationsFeedbackFragment = explanationsFeedbackFragment2;
        }
        explanationsFeedbackFragment.k = this;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment
    public final boolean Y() {
        return this.J;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment
    public final boolean b0() {
        return this.K;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        Window window = L().getWindow();
        if (window != null) {
            window.setSoftInputMode(16);
        }
    }
}
