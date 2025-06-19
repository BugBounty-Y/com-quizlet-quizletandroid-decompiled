package com.quizlet.explanations.databinding;

import android.view.View;
import androidx.cardview.widget.CardView;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes2.dex */
public final class t implements androidx.viewbinding.a {
    public final CardView a;
    public final AssemblyPrimaryButton b;
    public final QTextView c;
    public final QTextView d;

    public t(CardView cardView, AssemblyPrimaryButton assemblyPrimaryButton, QTextView qTextView, QTextView qTextView2) {
        this.a = cardView;
        this.b = assemblyPrimaryButton;
        this.c = qTextView;
        this.d = qTextView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
