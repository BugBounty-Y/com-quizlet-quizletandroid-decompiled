package com.quizlet.features.folders.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ boolean j;
    public final /* synthetic */ N k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public z(N n, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        z zVar = new z(this.k, hVar);
        zVar.j = ((Boolean) obj).booleanValue();
        return zVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Boolean bool = (Boolean) obj;
        bool.booleanValue();
        return ((z) create(bool, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        if (this.j) {
            N n = this.k;
            n.getClass();
            kotlinx.coroutines.E.A(p0.j(n), null, null, new u(n, null), 3);
        }
        return Unit.a;
    }
}
