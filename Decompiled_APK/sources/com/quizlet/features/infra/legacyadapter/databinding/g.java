package com.quizlet.features.infra.legacyadapter.databinding;

import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.features.infra.legacyadapter.common.UserListTitleView;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes3.dex */
public final class g implements androidx.viewbinding.a {
    public final CardView a;
    public final ConstraintLayout b;
    public final QTextView c;
    public final ImageView d;
    public final ImageView e;
    public final QTextView f;
    public final UserListTitleView g;
    public final ImageView h;
    public final TextView i;

    public g(CardView cardView, ConstraintLayout constraintLayout, QTextView qTextView, ImageView imageView, ImageView imageView2, QTextView qTextView2, UserListTitleView userListTitleView, ImageView imageView3, TextView textView) {
        this.a = cardView;
        this.b = constraintLayout;
        this.c = qTextView;
        this.d = imageView;
        this.e = imageView2;
        this.f = qTextView2;
        this.g = userListTitleView;
        this.h = imageView3;
        this.i = textView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
