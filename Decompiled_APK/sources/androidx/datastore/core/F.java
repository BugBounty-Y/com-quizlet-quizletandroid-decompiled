package androidx.datastore.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class F extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public int k;
    public /* synthetic */ boolean l;
    public final /* synthetic */ P m;
    public final /* synthetic */ int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(P p, int i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = p;
        this.n = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        F f = new F(this.m, this.n, hVar);
        f.l = ((Boolean) obj).booleanValue();
        return f;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Boolean bool = (Boolean) obj;
        bool.booleanValue();
        return ((F) create(bool, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0055  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x005a  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) {
        /*
            r6 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.k
            androidx.datastore.core.P r2 = r6.m
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L22
            if (r1 == r4) goto L1c
            if (r1 != r3) goto L14
            java.lang.Object r0 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L45
        L14:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1c:
            boolean r1 = r6.l
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L32
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            boolean r1 = r6.l
            r6.l = r1
            r6.k = r4
            java.lang.Object r7 = r2.i(r6)
            if (r7 != r0) goto L32
            goto L42
        L32:
            if (r1 == 0) goto L4c
            androidx.datastore.core.k0 r1 = r2.g()
            r6.j = r7
            r6.k = r3
            java.lang.Integer r1 = r1.a()
            if (r1 != r0) goto L43
        L42:
            return r0
        L43:
            r0 = r7
            r7 = r1
        L45:
            java.lang.Number r7 = (java.lang.Number) r7
            int r7 = r7.intValue()
            goto L51
        L4c:
            int r0 = r6.n
            r5 = r0
            r0 = r7
            r7 = r5
        L51:
            androidx.datastore.core.c r1 = new androidx.datastore.core.c
            if (r0 == 0) goto L5a
            int r2 = r0.hashCode()
            goto L5b
        L5a:
            r2 = 0
        L5b:
            r1.<init>(r0, r2, r7)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.F.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
