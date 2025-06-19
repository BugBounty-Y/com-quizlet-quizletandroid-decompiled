package androidx.datastore.core;

import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class D extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Throwable j;
    public int k;
    public /* synthetic */ boolean l;
    public final /* synthetic */ P m;
    public final /* synthetic */ int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(P p, int i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = p;
        this.n = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        D d = new D(this.m, this.n, hVar);
        d.l = ((Boolean) obj).booleanValue();
        return d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Boolean bool = (Boolean) obj;
        bool.booleanValue();
        return ((D) create(bool, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [int] */
    /* JADX WARN: Type inference failed for: r1v10 */
    /* JADX WARN: Type inference failed for: r1v14 */
    /* JADX WARN: Type inference failed for: r1v15 */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Throwable th;
        int iIntValue;
        boolean z;
        l0 l0Var;
        boolean z2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        boolean z3 = this.k;
        P p = this.m;
        try {
        } catch (Throwable th2) {
            if (z3 != 0) {
                k0 k0VarG = p.g();
                this.j = th2;
                this.l = z3;
                this.k = 2;
                Integer numA = k0VarG.a();
                if (numA != aVar) {
                    z = z3;
                    th = th2;
                    obj = numA;
                }
            } else {
                boolean z4 = z3;
                th = th2;
                iIntValue = this.n;
                z = z4;
            }
        }
        if (z3 == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            boolean z5 = this.l;
            this.l = z5;
            this.k = 1;
            obj = P.f(p, z5, this);
            z3 = z5;
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (z3 != 1) {
                if (z3 != 2) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                z = this.l;
                th = this.j;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                iIntValue = ((Number) obj).intValue();
                c0 c0Var = new c0(iIntValue, th);
                z2 = z;
                l0Var = c0Var;
                return new Pair(l0Var, Boolean.valueOf(z2));
            }
            boolean z6 = this.l;
            androidx.glance.appwidget.protobuf.Z.e(obj);
            z3 = z6;
        }
        l0Var = (l0) obj;
        z2 = z3;
        return new Pair(l0Var, Boolean.valueOf(z2));
    }
}
