package com.quizlet.features.setpage.header.ui;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.features.setpage.viewmodel.y;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ SetPageHeaderFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(SetPageHeaderFragment setPageHeaderFragment, h hVar) {
        super(2, hVar);
        this.k = setPageHeaderFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        d dVar = new d(this.k, hVar);
        dVar.j = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((com.quizlet.features.setpage.header.data.c) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.setpage.header.data.c cVar = (com.quizlet.features.setpage.header.data.c) this.j;
        if (!(cVar instanceof com.quizlet.features.setpage.header.data.c)) {
            throw new NoWhenBranchMatchedException();
        }
        long j = cVar.a;
        String str = SetPageHeaderFragment.m;
        P pV = this.k.V();
        pV.getClass();
        pV.H(new y(j, null));
        return Unit.a;
    }
}
