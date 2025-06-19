package com.quizlet.features.questiontypes.fitb;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ m j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        m mVar = this.j;
        boolean z = mVar.c.a.getBoolean("fillInTheBlankModalShown", false);
        d0 d0Var = mVar.j;
        if (z) {
            d0Var.h(Boolean.FALSE);
        } else {
            d0Var.h(Boolean.TRUE);
            assistantMode.refactored.a.p(mVar.c.a, "fillInTheBlankModalShown", true);
        }
        return Unit.a;
    }
}
