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
public final class c extends com.quizlet.baserecyclerview.b {
    public final C4196j c;

    public c(C4196j onCourseRemove) {
        Intrinsics.checkNotNullParameter(onCourseRemove, "onCourseRemove");
        s diffUtilCallback = new s(2);
        Intrinsics.checkNotNullParameter(diffUtilCallback, "diffUtilCallback");
        super((AbstractC1358c) diffUtilCallback);
        this.c = onCourseRemove;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.edgy.ui.recyclerview.viewholder.c holder = (com.quizlet.edgy.ui.recyclerview.viewholder.c) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        d dVar = (d) d(i);
        Intrinsics.d(dVar);
        holder.c(dVar);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        com.quizlet.edgy.databinding.f fVarA = com.quizlet.edgy.databinding.f.a(LayoutInflater.from(parent.getContext()).inflate(R.layout.listitem_course_selected, parent, false));
        Intrinsics.checkNotNullExpressionValue(fVarA, "inflate(...)");
        ConstraintLayout constraintLayout = fVarA.a;
        Intrinsics.checkNotNullExpressionValue(constraintLayout, "getRoot(...)");
        return new com.quizlet.edgy.ui.recyclerview.viewholder.c(constraintLayout, this.c);
    }
}
