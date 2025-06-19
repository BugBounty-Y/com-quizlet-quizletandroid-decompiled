package com.quizlet.explanations.solution.solutionwall;

import android.content.Context;
import android.view.View;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.cardview.widget.CardView;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class h extends com.quizlet.baserecyclerview.c {
    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.itemView;
        int i = R.id.button;
        AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.button, view);
        if (assemblyPrimaryButton != null) {
            i = R.id.logo;
            if (((AppCompatImageView) AbstractC3375o2.c(R.id.logo, view)) != null) {
                i = R.id.textview_description;
                if (((QTextView) AbstractC3375o2.c(R.id.textview_description, view)) != null) {
                    i = R.id.textview_title;
                    QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.textview_title, view);
                    if (qTextView != null) {
                        com.quizlet.explanations.databinding.c cVar = new com.quizlet.explanations.databinding.c((CardView) view, assemblyPrimaryButton, qTextView);
                        Intrinsics.checkNotNullExpressionValue(cVar, "bind(...)");
                        return cVar;
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(g item) {
        Intrinsics.checkNotNullParameter(item, "item");
        com.quizlet.explanations.databinding.c cVar = (com.quizlet.explanations.databinding.c) e();
        QTextView qTextView = cVar.c;
        com.quizlet.qutils.string.f fVarB = item.b();
        Context context = this.b;
        Intrinsics.checkNotNullExpressionValue(context, "<get-context>(...)");
        qTextView.setText(AbstractC3053s1.e(fVarB, context));
        cVar.b.setOnClickListener(new com.braze.ui.inappmessage.d(item, 20));
    }
}
