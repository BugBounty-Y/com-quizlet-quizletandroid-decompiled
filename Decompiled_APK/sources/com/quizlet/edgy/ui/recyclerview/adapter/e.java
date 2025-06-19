package com.quizlet.edgy.ui.recyclerview.adapter;

import android.view.LayoutInflater;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e extends AbstractC1361d0 {
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return 1;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.edgy.ui.recyclerview.viewholder.d holder = (com.quizlet.edgy.ui.recyclerview.viewholder.d) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        Unit item = Unit.a;
        holder.getClass();
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        com.quizlet.edgy.databinding.e eVarA = com.quizlet.edgy.databinding.e.a(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_popular_schools_text, parent, false));
        Intrinsics.checkNotNullExpressionValue(eVarA, "inflate(...)");
        ConstraintLayout view = eVarA.b;
        Intrinsics.checkNotNullExpressionValue(view, "getRoot(...)");
        Intrinsics.checkNotNullParameter(view, "view");
        return new com.quizlet.edgy.ui.recyclerview.viewholder.d(view);
    }
}
