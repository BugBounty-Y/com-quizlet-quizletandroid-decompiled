package com.quizlet.features.infra.legacyadapter.databinding;

import android.view.View;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.features.infra.legacyadapter.common.UserListTitleView;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes3.dex */
public final class e implements androidx.viewbinding.a {
    public final CardView a;
    public final ConstraintLayout b;
    public final QTextView c;
    public final UserListTitleView d;

    public e(CardView cardView, ConstraintLayout constraintLayout, QTextView qTextView, UserListTitleView userListTitleView) {
        this.a = cardView;
        this.b = constraintLayout;
        this.c = qTextView;
        this.d = userListTitleView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
