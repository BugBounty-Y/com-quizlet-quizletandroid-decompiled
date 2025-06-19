package com.quizlet.features.notes.detail.composables.magicnotesdetail;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class E extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.features.infra.folder.menu.viewmodel.n k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(com.quizlet.features.infra.folder.menu.viewmodel.n nVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        E e = new E(this.k, hVar);
        e.j = obj;
        return e;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((E) create((com.quizlet.features.infra.folder.menu.data.a) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.infra.folder.menu.data.a aVar2 = (com.quizlet.features.infra.folder.menu.data.a) this.j;
        if (!(aVar2 instanceof com.quizlet.features.infra.folder.menu.data.a)) {
            throw new NoWhenBranchMatchedException();
        }
        this.k.k(aVar2.a, aVar2.b, aVar2.c);
        return Unit.a;
    }
}
