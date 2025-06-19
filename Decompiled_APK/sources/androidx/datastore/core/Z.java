package androidx.datastore.core;

/* loaded from: classes.dex */
public final class Z extends S implements s0 {
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // androidx.datastore.core.s0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(java.lang.Object r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof androidx.datastore.core.Y
            if (r0 == 0) goto L13
            r0 = r7
            androidx.datastore.core.Y r0 = (androidx.datastore.core.Y) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.datastore.core.Y r0 = new androidx.datastore.core.Y
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            java.io.FileOutputStream r6 = r0.k
            java.io.FileOutputStream r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Throwable -> L2b
            goto L5d
        L2b:
            r6 = move-exception
            goto L6f
        L2d:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.util.concurrent.atomic.AtomicBoolean r7 = r5.c
            boolean r7 = r7.get()
            if (r7 != 0) goto L75
            java.io.FileOutputStream r7 = new java.io.FileOutputStream
            java.io.File r2 = r5.a
            r7.<init>(r2)
            androidx.datastore.core.f0 r2 = r5.b     // Catch: java.lang.Throwable -> L6d
            androidx.datastore.core.p0 r4 = new androidx.datastore.core.p0     // Catch: java.lang.Throwable -> L6d
            r4.<init>(r7)     // Catch: java.lang.Throwable -> L6d
            r0.j = r7     // Catch: java.lang.Throwable -> L6d
            r0.k = r7     // Catch: java.lang.Throwable -> L6d
            r0.n = r3     // Catch: java.lang.Throwable -> L6d
            kotlin.Unit r6 = r2.c(r6, r4)     // Catch: java.lang.Throwable -> L6d
            if (r6 != r1) goto L5b
            return r1
        L5b:
            r6 = r7
            r0 = r6
        L5d:
            java.io.FileDescriptor r6 = r6.getFD()     // Catch: java.lang.Throwable -> L2b
            r6.sync()     // Catch: java.lang.Throwable -> L2b
            kotlin.Unit r6 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L2b
            r6 = 0
            com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f.c(r0, r6)
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        L6d:
            r6 = move-exception
            r0 = r7
        L6f:
            throw r6     // Catch: java.lang.Throwable -> L70
        L70:
            r7 = move-exception
            com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f.c(r0, r6)
            throw r7
        L75:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "This scope has already been closed."
            r6.<init>(r7)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.Z.b(java.lang.Object, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
