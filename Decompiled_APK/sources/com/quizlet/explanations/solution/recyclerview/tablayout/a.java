package com.quizlet.explanations.solution.recyclerview.tablayout;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a extends com.quizlet.baserecyclerview.b {
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        c holder = (c) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        b bVar = (b) d(i);
        Intrinsics.d(bVar);
        holder.c(bVar);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View itemView = LayoutInflater.from(parent.getContext()).inflate(R.layout.listitem_explanations_solution_tab_layout, parent, false);
        Intrinsics.d(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        return new c(itemView);
    }
}
