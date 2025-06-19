package androidx.glance.session;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.glance.session.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1229g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ kotlin.jvm.internal.I k;
    public final /* synthetic */ kotlin.jvm.internal.I l;
    public final /* synthetic */ C1231i m;
    public final /* synthetic */ long n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1229g(kotlin.jvm.internal.I i, kotlin.jvm.internal.I i2, C1231i c1231i, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = i;
        this.l = i2;
        this.m = c1231i;
        this.n = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1229g(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1229g) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0033, code lost:
    
        if (kotlinx.coroutines.E.M(r9) == r0) goto L25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x0054, code lost:
    
        if (kotlinx.coroutines.E.n((r7 - r5) / 1000000, r9) == r0) goto L25;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.j
            androidx.glance.session.i r2 = r9.m
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L57
        L12:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L36
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlin.jvm.internal.I r10 = r9.k
            long r5 = r10.a
            kotlin.jvm.internal.I r10 = r9.l
            long r7 = r10.a
            int r10 = (r5 > r7 ? 1 : (r5 == r7 ? 0 : -1))
            if (r10 < 0) goto L49
            r9.j = r4
            java.lang.Object r10 = kotlinx.coroutines.E.M(r9)
            if (r10 != r0) goto L36
            goto L56
        L36:
            long r0 = r9.n
            androidx.compose.runtime.f r10 = r2.b
            r10.b(r0)
            java.lang.Object r10 = r2.c
            monitor-enter(r10)
            r2.e = r0     // Catch: java.lang.Throwable -> L46
            kotlin.Unit r0 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L46
            monitor-exit(r10)
            goto L6b
        L46:
            r0 = move-exception
            monitor-exit(r10)
            throw r0
        L49:
            long r7 = r7 - r5
            r4 = 1000000(0xf4240, double:4.940656E-318)
            long r7 = r7 / r4
            r9.j = r3
            java.lang.Object r10 = kotlinx.coroutines.E.n(r7, r9)
            if (r10 != r0) goto L57
        L56:
            return r0
        L57:
            r2.getClass()
            long r0 = java.lang.System.nanoTime()
            androidx.compose.runtime.f r10 = r2.b
            r10.b(r0)
            java.lang.Object r10 = r2.c
            monitor-enter(r10)
            r2.e = r0     // Catch: java.lang.Throwable -> L6e
            kotlin.Unit r0 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L6e
            monitor-exit(r10)
        L6b:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        L6e:
            r0 = move-exception
            monitor-exit(r10)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.session.C1229g.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
