package androidx.compose.animation.core;

import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.animation.core.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0232b extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public C0258o j;
    public kotlin.jvm.internal.F k;
    public int l;
    public final /* synthetic */ C0238e m;
    public final /* synthetic */ Object n;
    public final /* synthetic */ C0270u0 o;
    public final /* synthetic */ long p;
    public final /* synthetic */ Function1 q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0232b(C0238e c0238e, Object obj, C0270u0 c0270u0, long j, Function1 function1, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.m = c0238e;
        this.n = obj;
        this.o = c0270u0;
        this.p = j;
        this.q = function1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C0232b(this.m, this.n, this.o, this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C0232b) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.jvm.internal.F f;
        C0258o c0258o;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.l;
        int i2 = 1;
        C0238e c0238e = this.m;
        try {
            if (i == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                c0238e.c.c = (AbstractC0267t) c0238e.a.a.invoke(this.n);
                C0270u0 c0270u0 = this.o;
                ((androidx.compose.runtime.L0) c0238e.e).setValue(c0270u0.c);
                ((androidx.compose.runtime.L0) c0238e.d).setValue(Boolean.TRUE);
                C0258o c0258o2 = c0238e.c;
                C0258o c0258o3 = new C0258o(c0258o2.a, ((androidx.compose.runtime.L0) c0258o2.b).getValue(), AbstractC0240f.k(c0258o2.c), c0258o2.d, Long.MIN_VALUE, c0258o2.f);
                kotlin.jvm.internal.F f2 = new kotlin.jvm.internal.F();
                long j = this.p;
                C0230a c0230a = new C0230a(c0238e, c0258o3, this.q, f2, 0);
                this.j = c0258o3;
                this.k = f2;
                this.l = 1;
                if (AbstractC0240f.d(c0258o3, c0270u0, j, c0230a, this) == aVar) {
                    return aVar;
                }
                f = f2;
                c0258o = c0258o3;
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                f = this.k;
                c0258o = this.j;
                androidx.glance.appwidget.protobuf.Z.e(obj);
            }
            if (!f.a) {
                i2 = 2;
            }
            C0238e.b(c0238e);
            return new C0252l(i2, c0258o);
        } catch (CancellationException e) {
            C0238e.b(c0238e);
            throw e;
        }
    }
}
