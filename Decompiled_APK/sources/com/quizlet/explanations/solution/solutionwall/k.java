package com.quizlet.explanations.solution.solutionwall;

import android.content.Context;
import android.view.View;
import androidx.cardview.widget.CardView;
import com.google.android.gms.internal.measurement.AbstractC3088z1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.explanations.databinding.t;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.collections.A;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class k extends com.quizlet.baserecyclerview.c {
    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.itemView;
        int i = R.id.getStartedButton;
        AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.getStartedButton, view);
        if (assemblyPrimaryButton != null) {
            i = R.id.headerText;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.headerText, view);
            if (qTextView != null) {
                i = R.id.logInTextButton;
                QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.logInTextButton, view);
                if (qTextView2 != null) {
                    t tVar = new t((CardView) view, assemblyPrimaryButton, qTextView, qTextView2);
                    Intrinsics.checkNotNullExpressionValue(tVar, "bind(...)");
                    return tVar;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(final i item) {
        int i;
        Intrinsics.checkNotNullParameter(item, "item");
        QTextView qTextView = ((t) e()).c;
        int iOrdinal = item.a.ordinal();
        if (iOrdinal == 0) {
            i = R.string.create_a_free_account_header_exercise;
        } else {
            if (iOrdinal != 1) {
                throw new IllegalStateException();
            }
            i = R.string.create_a_free_account_header_question;
        }
        Context context = this.b;
        String string = context.getString(i);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        qTextView.setText(string);
        QTextView qTextView2 = ((t) e()).d;
        String string2 = context.getString(R.string.log_in_text);
        Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
        String string3 = context.getString(R.string.already_have_an_account_text, string2);
        Intrinsics.checkNotNullExpressionValue(string3, "getString(...)");
        Intrinsics.checkNotNullExpressionValue(context, "<get-context>(...)");
        qTextView2.setText(AbstractC3088z1.b(string3, A.b(new com.quizlet.qutils.string.h(string2, com.quizlet.themes.extensions.a.a(context, R.attr.AssemblyLinkText)))));
        final int i2 = 0;
        ((t) e()).b.setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.explanations.solution.solutionwall.j
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                switch (i2) {
                    case 0:
                        item.b.invoke();
                        break;
                    default:
                        item.c.invoke();
                        break;
                }
            }
        });
        final int i3 = 1;
        ((t) e()).d.setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.explanations.solution.solutionwall.j
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                switch (i3) {
                    case 0:
                        item.b.invoke();
                        break;
                    default:
                        item.c.invoke();
                        break;
                }
            }
        });
    }
}
