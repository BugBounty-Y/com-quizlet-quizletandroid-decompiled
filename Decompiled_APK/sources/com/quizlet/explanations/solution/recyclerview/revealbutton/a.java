package com.quizlet.explanations.solution.recyclerview.revealbutton;

import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.F0;
import com.braze.ui.inappmessage.d;
import com.quizlet.explanations.databinding.u;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a extends com.quizlet.baserecyclerview.b {
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        c holder = (c) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        b item = (b) d(i);
        Intrinsics.d(item);
        holder.getClass();
        Intrinsics.checkNotNullParameter(item, "item");
        ((u) holder.e()).b.setOnClickListener(new d(item, 19));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View itemView = com.quizlet.baserecyclerview.b.g(parent, R.layout.listitem_explanations_solution_reveal_buttons);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        return new c(itemView);
    }
}
