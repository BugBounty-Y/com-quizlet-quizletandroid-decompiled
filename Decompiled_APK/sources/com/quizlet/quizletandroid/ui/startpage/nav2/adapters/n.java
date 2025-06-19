package com.quizlet.quizletandroid.ui.startpage.nav2.adapters;

import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.J;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n extends a {
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        int i2 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.q.d;
        return R.layout.home_rateus;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.q holder = (com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.q) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        View view = ((J) d(i)).d.a;
        holder.getClass();
        Intrinsics.checkNotNullParameter(view, "view");
        ViewParent parent = view.getParent();
        ViewGroup viewGroup = parent instanceof ViewGroup ? (ViewGroup) parent : null;
        if (viewGroup != null) {
            viewGroup.removeView(view);
        }
        View view2 = holder.itemView;
        Intrinsics.e(view2, "null cannot be cast to non-null type android.widget.FrameLayout");
        ((FrameLayout) view2).addView(view);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View itemView = com.quizlet.baserecyclerview.b.g(parent, i);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        return new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.q(itemView);
    }
}
