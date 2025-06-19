package coil3.decode;

/* loaded from: classes.dex */
public final class e implements k {
    public final q a;
    public final coil3.request.m b;
    public final kotlinx.coroutines.sync.i c;
    public final n d;

    public e(q qVar, coil3.request.m mVar, kotlinx.coroutines.sync.i iVar, n nVar) {
        this.a = qVar;
        this.b = mVar;
        this.c = iVar;
        this.d = nVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // coil3.decode.k
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            r7 = this;
            boolean r0 = r8 instanceof coil3.decode.d
            if (r0 == 0) goto L13
            r0 = r8
            coil3.decode.d r0 = (coil3.decode.d) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            coil3.decode.d r0 = new coil3.decode.d
            r0.<init>(r7, r8)
        L18:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L43
            if (r2 == r4) goto L38
            if (r2 != r3) goto L30
            java.lang.Object r0 = r0.j
            kotlinx.coroutines.sync.e r0 = (kotlinx.coroutines.sync.e) r0
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Throwable -> L2e
            goto L75
        L2e:
            r8 = move-exception
            goto L83
        L30:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L38:
            kotlinx.coroutines.sync.i r2 = r0.k
            java.lang.Object r4 = r0.j
            coil3.decode.e r4 = (coil3.decode.e) r4
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r8 = r2
            goto L56
        L43:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r7
            kotlinx.coroutines.sync.i r8 = r7.c
            r0.k = r8
            r0.n = r4
            java.lang.Object r2 = r8.a(r0)
            if (r2 != r1) goto L55
            goto L71
        L55:
            r4 = r7
        L56:
            androidx.lifecycle.h r2 = new androidx.lifecycle.h     // Catch: java.lang.Throwable -> L81
            r5 = 9
            r2.<init>(r4, r5)     // Catch: java.lang.Throwable -> L81
            r0.j = r8     // Catch: java.lang.Throwable -> L81
            r4 = 0
            r0.k = r4     // Catch: java.lang.Throwable -> L81
            r0.n = r3     // Catch: java.lang.Throwable -> L81
            kotlin.coroutines.n r3 = kotlin.coroutines.n.a     // Catch: java.lang.Throwable -> L81
            kotlinx.coroutines.g0 r5 = new kotlinx.coroutines.g0     // Catch: java.lang.Throwable -> L81
            r5.<init>(r2, r4)     // Catch: java.lang.Throwable -> L81
            java.lang.Object r0 = kotlinx.coroutines.E.J(r3, r5, r0)     // Catch: java.lang.Throwable -> L81
            if (r0 != r1) goto L72
        L71:
            return r1
        L72:
            r6 = r0
            r0 = r8
            r8 = r6
        L75:
            coil3.decode.i r8 = (coil3.decode.i) r8     // Catch: java.lang.Throwable -> L2e
            kotlinx.coroutines.sync.h r0 = (kotlinx.coroutines.sync.h) r0
            r0.c()
            return r8
        L7d:
            r6 = r0
            r0 = r8
            r8 = r6
            goto L83
        L81:
            r0 = move-exception
            goto L7d
        L83:
            kotlinx.coroutines.sync.h r0 = (kotlinx.coroutines.sync.h) r0
            r0.c()
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.decode.e.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
