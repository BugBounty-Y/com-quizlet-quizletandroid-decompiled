package com.quizlet.explanations.myexplanations.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.I;

/* loaded from: classes2.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ m k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        i iVar = new i(this.k, hVar);
        iVar.j = obj;
        return iVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        C c = (C) this.j;
        m mVar = this.k;
        I iF = E.f(c, null, new h(mVar, null), 3);
        E.A(c, null, null, new e(mVar, iF, null), 3);
        E.A(c, null, null, new f(mVar, iF, null), 3);
        E.A(c, null, null, new g(mVar, iF, null), 3);
        mVar.e.d(mVar.h, null);
        return Unit.a;
    }
}
