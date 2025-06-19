package com.quizlet.quizletandroid.ui.startpage.nav2.adapters;

import android.content.Context;
import android.view.ViewGroup;
import androidx.compose.ui.platform.ComposeView;
import androidx.recyclerview.widget.F0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends a {
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        return 102;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        c holder = (c) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        Object objD = d(i);
        Intrinsics.checkNotNullExpressionValue(objD, "getItem(...)");
        com.quizlet.quizletandroid.ui.startpage.nav2.model.r item = (com.quizlet.quizletandroid.ui.startpage.nav2.model.r) objD;
        holder.getClass();
        Intrinsics.checkNotNullParameter(item, "item");
        holder.d.setContent(new androidx.compose.runtime.internal.d(true, -1453977086, new b(item, 1)));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        Context context = parent.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        return new c(new ComposeView(context, null, 6));
    }
}
