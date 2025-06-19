package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.cardview.widget.CardView;
import com.quizlet.partskit.widgets.QTextView;

/* renamed from: com.quizlet.quizletandroid.databinding.t, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4615t implements androidx.viewbinding.a {
    public final CardView a;
    public final CardView b;
    public final QTextView c;

    public C4615t(CardView cardView, CardView cardView2, QTextView qTextView) {
        this.a = cardView;
        this.b = cardView2;
        this.c = qTextView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
