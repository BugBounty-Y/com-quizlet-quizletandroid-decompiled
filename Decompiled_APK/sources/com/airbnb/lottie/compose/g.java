package com.airbnb.lottie.compose;

import androidx.compose.runtime.L0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public final /* synthetic */ h j;
    public final /* synthetic */ com.airbnb.lottie.h k;
    public final /* synthetic */ float l;
    public final /* synthetic */ boolean m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(h hVar, com.airbnb.lottie.h hVar2, float f, boolean z, kotlin.coroutines.h hVar3) {
        super(1, hVar3);
        this.j = hVar;
        this.k = hVar2;
        this.l = f;
        this.m = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new g(this.j, this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((g) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        h hVar = this.j;
        ((L0) hVar.i).setValue(this.k);
        hVar.h(this.l);
        hVar.g(1);
        h.b(hVar, false);
        if (this.m) {
            ((L0) hVar.l).setValue(Long.MIN_VALUE);
        }
        return Unit.a;
    }
}
