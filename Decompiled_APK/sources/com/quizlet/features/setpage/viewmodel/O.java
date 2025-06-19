package com.quizlet.features.setpage.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class O extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public final /* synthetic */ P j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public O(P p, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.j = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new O(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((O) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        P p = this.j;
        p.J.c(new com.quizlet.assembly.compose.buttons.Z(8));
        return new com.quizlet.features.infra.basestudy.data.models.o(p.D(), null);
    }
}
