package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.ImageView;
import androidx.cardview.widget.CardView;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes3.dex */
public final class K implements androidx.viewbinding.a {
    public final CardView a;
    public final ImageView b;
    public final QTextView c;
    public final QTextView d;
    public final QTextView e;

    public K(CardView cardView, ImageView imageView, QTextView qTextView, QTextView qTextView2, QTextView qTextView3) {
        this.a = cardView;
        this.b = imageView;
        this.c = qTextView;
        this.d = qTextView2;
        this.e = qTextView3;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
