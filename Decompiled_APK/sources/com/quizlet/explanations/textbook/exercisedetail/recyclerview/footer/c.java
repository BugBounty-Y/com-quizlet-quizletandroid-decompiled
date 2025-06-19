package com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer;

import android.view.ViewGroup;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends com.quizlet.baserecyclerview.b {
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        e holder = (e) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        h hVar = (h) d(i);
        Intrinsics.e(hVar, "null cannot be cast to non-null type com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.NextUpFooter");
        holder.c(hVar);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        return new e(com.quizlet.baserecyclerview.b.g(parent, R.layout.listitem_exercise_detail_next));
    }
}
