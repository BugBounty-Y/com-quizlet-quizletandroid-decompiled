package com.quizlet.features.practicetest.detail;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.quizlet.features.practicetest.detail.viewmodel.a j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(com.quizlet.features.practicetest.detail.viewmodel.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.practicetest.detail.viewmodel.i iVar = (com.quizlet.features.practicetest.detail.viewmodel.i) this.j;
        E.A(p0.j(iVar), iVar.p, null, new com.quizlet.features.practicetest.detail.viewmodel.f(iVar, null), 2);
        return Unit.a;
    }
}
