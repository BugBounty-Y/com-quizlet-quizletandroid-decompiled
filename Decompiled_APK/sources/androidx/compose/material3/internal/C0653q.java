package androidx.compose.material3.internal;

import androidx.compose.material.C0560c;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material3.internal.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0653q extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ androidx.work.impl.model.t k;
    public final /* synthetic */ Object l;
    public final /* synthetic */ C0560c m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0653q(androidx.work.impl.model.t tVar, Object obj, C0560c c0560c, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = tVar;
        this.l = obj;
        this.m = c0560c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C0653q(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C0653q) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            Object obj2 = this.l;
            androidx.work.impl.model.t tVar = this.k;
            tVar.v(obj2);
            C0648l c0648l = new C0648l(tVar, 1);
            C0652p c0652p = new C0652p(this.m, tVar, null);
            this.j = 1;
            if (AbstractC0646j.b(c0648l, c0652p, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
