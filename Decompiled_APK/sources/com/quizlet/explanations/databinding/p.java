package com.quizlet.explanations.databinding;

import android.view.View;
import androidx.cardview.widget.CardView;
import com.quizlet.assembly.widgets.AssemblyPill;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes2.dex */
public final class p implements androidx.viewbinding.a {
    public final CardView a;
    public final QTextView b;
    public final AssemblyPill c;

    public p(CardView cardView, QTextView qTextView, AssemblyPill assemblyPill) {
        this.a = cardView;
        this.b = qTextView;
        this.c = assemblyPill;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
