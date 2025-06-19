package com.quizlet.quizletandroid.ui.usersettings.adapters;

import android.graphics.drawable.Drawable;
import android.view.View;
import com.quizlet.quizletandroid.databinding.k0;
import com.quizlet.quizletandroid.ui.common.adapter.viewholder.h;
import com.quizlet.quizletandroid.ui.usersettings.fragments.ChangeProfileImageFragment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends com.quizlet.baserecyclerview.c {
    public final ChangeProfileImageFragment d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(View view, ChangeProfileImageFragment presenter) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(presenter, "presenter");
        this.d = presenter;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        Drawable item = (Drawable) obj;
        Intrinsics.checkNotNullParameter(item, "item");
        ((k0) e()).b.setImageDrawable(item);
        this.itemView.setOnClickListener(new h(this, 24));
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        k0 k0VarA = k0.a(this.a);
        Intrinsics.checkNotNullExpressionValue(k0VarA, "bind(...)");
        return k0VarA;
    }
}
