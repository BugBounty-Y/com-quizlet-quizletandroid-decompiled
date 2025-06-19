package com.quizlet.explanations.feedback.ui.fragments;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.explanations.databinding.m;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes2.dex */
public final class ThanksForReportingFragment extends Hilt_ThanksForReportingFragment<m> {
    public static final String k;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.explanations.feedback.viewmodel.a.class), new j(this, 0), new j(this, 2), new j(this, 1));

    static {
        Intrinsics.checkNotNullExpressionValue("ThanksForReportingFragment", "getSimpleName(...)");
        k = "ThanksForReportingFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return k;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_thanks_for_reporting, viewGroup, false);
        int i = R.id.doneButton;
        AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.doneButton, viewInflate);
        if (assemblyPrimaryButton != null) {
            i = R.id.propsGraphic;
            if (((ImageView) AbstractC3375o2.c(R.id.propsGraphic, viewInflate)) != null) {
                i = R.id.thanksHeader;
                if (((QTextView) AbstractC3375o2.c(R.id.thanksHeader, viewInflate)) != null) {
                    i = R.id.thanksMessage;
                    if (((QTextView) AbstractC3375o2.c(R.id.thanksMessage, viewInflate)) != null) {
                        m mVar = new m((ConstraintLayout) viewInflate, assemblyPrimaryButton);
                        Intrinsics.checkNotNullExpressionValue(mVar, "inflate(...)");
                        return mVar;
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        m mVar = (m) J();
        mVar.b.setOnClickListener(new com.braze.ui.inappmessage.d(this, 18));
    }
}
