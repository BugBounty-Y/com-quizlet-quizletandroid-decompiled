package com.quizlet.quizletandroid.ui.setcreation.fragments;

import androidx.recyclerview.widget.B0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.generated.enums.O1;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class EditSetFragment$initView$1 extends LinearLayoutManager {
    public final /* synthetic */ EditSetFragment E;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public EditSetFragment$initView$1(EditSetFragment editSetFragment, dagger.hilt.android.internal.managers.j jVar) {
        super(jVar);
        this.E = editSetFragment;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final void F0(RecyclerView recyclerView, B0 b0, int i) {
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        androidx.core.util.c cVar = this.E.B;
        Integer numValueOf = null;
        O1 o1 = cVar == null ? null : (O1) cVar.a;
        if (o1 == O1.WORD) {
            float f = com.quizlet.quizletandroid.ui.setcreation.viewholders.m.l;
            numValueOf = Integer.valueOf(R.id.edit_set_word_field);
        } else if (o1 == O1.DEFINITION) {
            float f2 = com.quizlet.quizletandroid.ui.setcreation.viewholders.m.l;
            numValueOf = Integer.valueOf(R.id.edit_set_definition_field);
        }
        com.quizlet.quizletandroid.ui.setcreation.scrolling.a aVar = new com.quizlet.quizletandroid.ui.setcreation.scrolling.a(recyclerView.getContext());
        aVar.q = numValueOf;
        aVar.r = 500.0f;
        int iComputeVerticalScrollRange = recyclerView.computeVerticalScrollRange();
        aVar.a = i;
        aVar.s = iComputeVerticalScrollRange;
        aVar.r = kotlin.ranges.l.b(i * 10.0f, 500.0f, 2000.0f);
        G0(aVar);
    }
}
