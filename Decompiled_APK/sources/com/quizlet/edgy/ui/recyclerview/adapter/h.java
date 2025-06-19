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
public final class h extends com.quizlet.baserecyclerview.b {
    public final C4196j c;

    public h(C4196j onSchoolSelected) {
        Intrinsics.checkNotNullParameter(onSchoolSelected, "onSchoolSelected");
        s diffUtilCallback = new s(2);
        Intrinsics.checkNotNullParameter(diffUtilCallback, "diffUtilCallback");
        super((AbstractC1358c) diffUtilCallback);
        this.c = onSchoolSelected;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.edgy.ui.recyclerview.viewholder.f holder = (com.quizlet.edgy.ui.recyclerview.viewholder.f) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        i iVar = (i) d(i);
        Intrinsics.d(iVar);
        holder.c(iVar);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        com.quizlet.edgy.databinding.h hVarA = com.quizlet.edgy.databinding.h.a(LayoutInflater.from(parent.getContext()).inflate(R.layout.listitem_search_school, parent, false));
        Intrinsics.checkNotNullExpressionValue(hVarA, "inflate(...)");
        ConstraintLayout constraintLayout = hVarA.a;
        Intrinsics.checkNotNullExpressionValue(constraintLayout, "getRoot(...)");
        return new com.quizlet.edgy.ui.recyclerview.viewholder.f(constraintLayout, this.c);
    }
}
