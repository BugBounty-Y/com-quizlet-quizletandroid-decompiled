package androidx.compose.runtime;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.runtime.s0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0820s0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0830u0 l;
    public final /* synthetic */ W m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0820s0(C0830u0 c0830u0, W w, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0830u0;
        this.m = w;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0820s0 c0820s0 = new C0820s0(this.l, this.m, hVar);
        c0820s0.k = obj;
        return c0820s0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0820s0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
            return Unit.a;
        }
        androidx.glance.appwidget.protobuf.Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
        this.j = 1;
        this.l.invoke(c, this.m, this);
        return aVar;
    }
}
