package com.quizlet.explanations.questiondetail.recyclerview;

import android.content.Context;
import android.view.ViewGroup;
import androidx.compose.ui.platform.ComposeView;
import androidx.recyclerview.widget.F0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a extends com.quizlet.baserecyclerview.b {
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        c holder = (c) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        Object objD = d(i);
        Intrinsics.checkNotNullExpressionValue(objD, "getItem(...)");
        com.quizlet.explanations.questiondetail.data.e item = (com.quizlet.explanations.questiondetail.data.e) objD;
        holder.getClass();
        Intrinsics.checkNotNullParameter(item, "item");
        holder.d.setContent(new androidx.compose.runtime.internal.d(true, 322160228, new b(item, 1)));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        Context context = parent.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        return new c(new ComposeView(context, null, 6));
    }
}
