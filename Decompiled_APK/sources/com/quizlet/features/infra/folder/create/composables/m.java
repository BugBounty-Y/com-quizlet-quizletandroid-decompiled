package com.quizlet.features.infra.folder.create.composables;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ kotlin.jvm.functions.d k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(kotlin.jvm.functions.d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        m mVar = new m(this.k, hVar);
        mVar.j = obj;
        return mVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((com.quizlet.features.infra.folder.create.coursefolder.data.n) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.infra.folder.create.coursefolder.data.n nVar = (com.quizlet.features.infra.folder.create.coursefolder.data.n) this.j;
        this.k.invoke(nVar.a, "", new Long(nVar.b), new Long(nVar.c));
        return Unit.a;
    }
}
