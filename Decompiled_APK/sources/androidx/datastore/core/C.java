package androidx.datastore.core;

import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public Throwable j;
    public int k;
    public final /* synthetic */ P l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(P p, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.l = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Throwable th;
        l0 c0Var;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        P p = this.l;
        try {
        } catch (Throwable th2) {
            k0 k0VarG = p.g();
            this.j = th2;
            this.k = 2;
            Integer numA = k0VarG.a();
            if (numA != aVar) {
                th = th2;
                obj = numA;
            }
        }
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            this.k = 1;
            obj = P.f(p, true, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                if (i != 2) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                th = this.j;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                c0Var = new c0(((Number) obj).intValue(), th);
                return new Pair(c0Var, Boolean.TRUE);
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        c0Var = (l0) obj;
        return new Pair(c0Var, Boolean.TRUE);
    }
}
