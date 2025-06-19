package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.C4987d;

/* renamed from: androidx.paging.l0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1326l0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ kotlinx.coroutines.channels.h l;
    public final /* synthetic */ C1336q0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1326l0(C1336q0 c1336q0, kotlin.coroutines.h hVar, kotlinx.coroutines.channels.h hVar2) {
        super(2, hVar);
        this.l = hVar2;
        this.m = c1336q0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1326l0 c1326l0 = new C1326l0(this.m, hVar, this.l);
        c1326l0.k = obj;
        return c1326l0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1326l0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
            C4987d c4987dK = kotlinx.coroutines.flow.e0.k(this.l);
            C1324k0 c1324k0 = new C1324k0(this.m, c);
            this.j = 1;
            if (c4987dK.b(c1324k0, this) == aVar) {
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
