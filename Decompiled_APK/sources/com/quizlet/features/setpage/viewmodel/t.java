package com.quizlet.features.setpage.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ P j;
    public final /* synthetic */ com.quizlet.features.infra.folder.menu.data.q k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(P p, com.quizlet.features.infra.folder.menu.data.q qVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = p;
        this.k = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new t(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.j.L.e(((com.quizlet.features.infra.folder.menu.data.o) this.k).b);
        return Unit.a;
    }
}
