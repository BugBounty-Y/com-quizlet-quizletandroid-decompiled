package com.braze.managers;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.braze.managers.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1499l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int a;
    public final /* synthetic */ C1500m b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1499l(C1500m c1500m, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.b = c1500m;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1499l(this.b, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new C1499l(this.b, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.a;
        if (i == 0) {
            Z.e(obj);
            this.a = 1;
            if (kotlinx.coroutines.E.n(1000L, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        C1500m c1500m = this.b;
        c1500m.getClass();
        c1500m.a(new com.braze.models.outgoing.j());
        return Unit.a;
    }
}
