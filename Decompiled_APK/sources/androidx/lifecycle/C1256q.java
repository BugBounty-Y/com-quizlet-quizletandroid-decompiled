package androidx.lifecycle;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* renamed from: androidx.lifecycle.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1256q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C l;
    public final /* synthetic */ B m;
    public final /* synthetic */ InterfaceC4992i n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1256q(C c, B b, InterfaceC4992i interfaceC4992i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c;
        this.m = b;
        this.n = interfaceC4992i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1256q c1256q = new C1256q(this.l, this.m, this.n, hVar);
        c1256q.k = obj;
        return c1256q;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1256q) create((kotlinx.coroutines.channels.u) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlinx.coroutines.channels.u uVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            kotlinx.coroutines.channels.u uVar2 = (kotlinx.coroutines.channels.u) this.k;
            C1255p c1255p = new C1255p(this.n, uVar2, null);
            this.k = uVar2;
            this.j = 1;
            if (p0.l(this.l, this.m, c1255p, this) == aVar) {
                return aVar;
            }
            uVar = uVar2;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            uVar = (kotlinx.coroutines.channels.u) this.k;
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        ((kotlinx.coroutines.channels.t) uVar).n0(null);
        return Unit.a;
    }
}
