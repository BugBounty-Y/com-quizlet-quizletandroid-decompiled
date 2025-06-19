package com.quizlet.quizletandroid.ui.startpage.nav2.adapters;

import android.content.Context;
import android.view.ViewGroup;
import androidx.compose.ui.platform.ComposeView;
import androidx.recyclerview.widget.F0;
import com.onetrust.otpublishers.headless.UI.adapter.s;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m extends a {
    public final com.quizlet.quizletandroid.ui.globalnav.composable.n c;

    public m(com.quizlet.quizletandroid.ui.globalnav.composable.n onClick) {
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        s diffUtilCallback = new s(2);
        Intrinsics.checkNotNullParameter(diffUtilCallback, "diffUtilCallback");
        super(diffUtilCallback);
        this.c = onClick;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.baserecyclerview.c holder = (com.quizlet.baserecyclerview.c) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        Object objD = d(i);
        Intrinsics.checkNotNullExpressionValue(objD, "getItem(...)");
        holder.c(objD);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        Context context = parent.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        return new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.p(this.c, new ComposeView(context, null, 6));
    }
}
