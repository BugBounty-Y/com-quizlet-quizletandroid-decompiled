package com.quizlet.explanations.textbook.tableofcontents.recyclerview;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class h extends AbstractC1361d0 {
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return 1;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        g holder = (g) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View itemView = LayoutInflater.from(parent.getContext()).inflate(R.layout.listitem_empty_textbook_content, parent, false);
        Intrinsics.d(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        return new g(itemView);
    }
}
