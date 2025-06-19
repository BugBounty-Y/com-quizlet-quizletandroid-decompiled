package com.quizlet.edgy.ui.recyclerview.adapter;

import android.view.LayoutInflater;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.quizlet.edgy.ui.fragment.C4192f;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a extends AbstractC1361d0 {
    public final C4192f a;

    public a(C4192f onClicked) {
        Intrinsics.checkNotNullParameter(onClicked, "onClicked");
        this.a = onClicked;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return 1;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.edgy.ui.recyclerview.viewholder.a holder = (com.quizlet.edgy.ui.recyclerview.viewholder.a) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        holder.c(Unit.a);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        com.quizlet.edgy.databinding.d dVarA = com.quizlet.edgy.databinding.d.a(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_add_manually_button, parent, false));
        Intrinsics.checkNotNullExpressionValue(dVarA, "inflate(...)");
        ConstraintLayout constraintLayout = dVarA.a;
        Intrinsics.checkNotNullExpressionValue(constraintLayout, "getRoot(...)");
        return new com.quizlet.edgy.ui.recyclerview.viewholder.a(constraintLayout, this.a);
    }
}
