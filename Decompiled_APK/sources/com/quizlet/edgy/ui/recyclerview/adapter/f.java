package com.quizlet.edgy.ui.recyclerview.adapter;

import android.view.LayoutInflater;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.AbstractC1358c;
import androidx.recyclerview.widget.F0;
import com.onetrust.otpublishers.headless.UI.adapter.s;
import com.quizlet.edgy.ui.fragment.C4196j;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f extends com.quizlet.baserecyclerview.b {
    public final C4196j c;

    public f(C4196j onCourseSelected) {
        Intrinsics.checkNotNullParameter(onCourseSelected, "onCourseSelected");
        s diffUtilCallback = new s(2);
        Intrinsics.checkNotNullParameter(diffUtilCallback, "diffUtilCallback");
        super((AbstractC1358c) diffUtilCallback);
        this.c = onCourseSelected;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.edgy.ui.recyclerview.viewholder.e holder = (com.quizlet.edgy.ui.recyclerview.viewholder.e) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        g gVar = (g) d(i);
        Intrinsics.d(gVar);
        holder.c(gVar);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        com.quizlet.edgy.databinding.g gVarA = com.quizlet.edgy.databinding.g.a(LayoutInflater.from(parent.getContext()).inflate(R.layout.listitem_search_course, parent, false));
        Intrinsics.checkNotNullExpressionValue(gVarA, "inflate(...)");
        ConstraintLayout constraintLayout = gVarA.a;
        Intrinsics.checkNotNullExpressionValue(constraintLayout, "getRoot(...)");
        return new com.quizlet.edgy.ui.recyclerview.viewholder.e(constraintLayout, this.c);
    }
}
