package androidx.datastore.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class O extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlin.jvm.internal.H j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ kotlin.jvm.internal.H m;
    public final /* synthetic */ P n;
    public final /* synthetic */ Object o;
    public final /* synthetic */ boolean p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public O(kotlin.jvm.internal.H h, P p, Object obj, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = h;
        this.n = p;
        this.o = obj;
        this.p = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        O o = new O(this.m, this.n, this.o, this.p, hVar);
        o.l = obj;
        return o;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((O) create((s0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x0062, code lost:
    
        if (r6.b(r3, r7) == r0) goto L16;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.k
            kotlin.jvm.internal.H r2 = r7.m
            java.lang.Object r3 = r7.o
            androidx.datastore.core.P r4 = r7.n
            r5 = 2
            r6 = 1
            if (r1 == 0) goto L28
            if (r1 == r6) goto L1e
            if (r1 != r5) goto L16
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L65
        L16:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1e:
            kotlin.jvm.internal.H r1 = r7.j
            java.lang.Object r6 = r7.l
            androidx.datastore.core.s0 r6 = (androidx.datastore.core.s0) r6
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4f
        L28:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Object r8 = r7.l
            androidx.datastore.core.s0 r8 = (androidx.datastore.core.s0) r8
            androidx.datastore.core.k0 r1 = r4.g()
            r7.l = r8
            r7.j = r2
            r7.k = r6
            androidx.appcompat.app.Q r1 = r1.b
            java.lang.Object r1 = r1.a
            java.util.concurrent.atomic.AtomicInteger r1 = (java.util.concurrent.atomic.AtomicInteger) r1
            int r1 = r1.incrementAndGet()
            java.lang.Integer r6 = new java.lang.Integer
            r6.<init>(r1)
            if (r6 != r0) goto L4b
            goto L64
        L4b:
            r1 = r6
            r6 = r8
            r8 = r1
            r1 = r2
        L4f:
            java.lang.Number r8 = (java.lang.Number) r8
            int r8 = r8.intValue()
            r1.a = r8
            r8 = 0
            r7.l = r8
            r7.j = r8
            r7.k = r5
            java.lang.Object r8 = r6.b(r3, r7)
            if (r8 != r0) goto L65
        L64:
            return r0
        L65:
            boolean r8 = r7.p
            if (r8 == 0) goto L7d
            androidx.webkit.internal.p r8 = r4.h
            androidx.datastore.core.c r0 = new androidx.datastore.core.c
            if (r3 == 0) goto L74
            int r1 = r3.hashCode()
            goto L75
        L74:
            r1 = 0
        L75:
            int r2 = r2.a
            r0.<init>(r3, r1, r2)
            r8.w(r0)
        L7d:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.O.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
