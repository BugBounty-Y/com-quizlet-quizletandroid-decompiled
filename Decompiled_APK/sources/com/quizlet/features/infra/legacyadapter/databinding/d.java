package com.quizlet.features.infra.legacyadapter.databinding;

import android.view.View;
import androidx.cardview.widget.CardView;
import com.quizlet.features.infra.legacyadapter.common.UserListTitleView;

/* loaded from: classes3.dex */
public final class d implements androidx.viewbinding.a {
    public final CardView a;
    public final UserListTitleView b;

    public d(CardView cardView, UserListTitleView userListTitleView) {
        this.a = cardView;
        this.b = userListTitleView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
