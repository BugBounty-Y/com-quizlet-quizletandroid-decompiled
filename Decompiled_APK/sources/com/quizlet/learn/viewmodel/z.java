package com.quizlet.learn.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ G j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public z(G g, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new z(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((z) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        List list = G.D1;
        G g = this.j;
        com.quizlet.features.infra.basestudy.manager.f fVar = g.Z;
        g.M.j(new com.quizlet.learn.data.D(g.d1, fVar.g(), fVar.x.c()));
        return Unit.a;
    }
}
