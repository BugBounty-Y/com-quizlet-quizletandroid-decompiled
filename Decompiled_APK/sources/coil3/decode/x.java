package coil3.decode;

import android.graphics.ImageDecoder;

/* loaded from: classes.dex */
public final class x implements k {
    public final ImageDecoder.Source a;
    public final AutoCloseable b;
    public final coil3.request.m c;
    public final kotlinx.coroutines.sync.i d;

    public x(ImageDecoder.Source source, AutoCloseable autoCloseable, coil3.request.m mVar, kotlinx.coroutines.sync.i iVar) {
        this.a = source;
        this.b = autoCloseable;
        this.c = mVar;
        this.d = iVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // coil3.decode.k
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof coil3.decode.v
            if (r0 == 0) goto L13
            r0 = r6
            coil3.decode.v r0 = (coil3.decode.v) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            coil3.decode.v r0 = new coil3.decode.v
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            kotlinx.coroutines.sync.i r1 = r0.k
            coil3.decode.x r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L47
        L2b:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            kotlinx.coroutines.sync.i r6 = r5.d
            r0.k = r6
            r0.n = r3
            java.lang.Object r0 = r6.a(r0)
            if (r0 != r1) goto L45
            return r1
        L45:
            r0 = r5
            r1 = r6
        L47:
            java.lang.AutoCloseable r6 = r0.b     // Catch: java.lang.Throwable -> L6d
            kotlin.jvm.internal.F r2 = new kotlin.jvm.internal.F     // Catch: java.lang.Throwable -> L6f
            r2.<init>()     // Catch: java.lang.Throwable -> L6f
            android.graphics.ImageDecoder$Source r3 = r0.a     // Catch: java.lang.Throwable -> L6f
            coil3.decode.w r4 = new coil3.decode.w     // Catch: java.lang.Throwable -> L6f
            r4.<init>(r0, r2)     // Catch: java.lang.Throwable -> L6f
            android.graphics.Bitmap r0 = androidx.webkit.internal.f.c(r3, r4)     // Catch: java.lang.Throwable -> L6f
            coil3.decode.i r3 = new coil3.decode.i     // Catch: java.lang.Throwable -> L6f
            coil3.a r4 = new coil3.a     // Catch: java.lang.Throwable -> L6f
            r4.<init>(r0)     // Catch: java.lang.Throwable -> L6f
            boolean r0 = r2.a     // Catch: java.lang.Throwable -> L6f
            r3.<init>(r4, r0)     // Catch: java.lang.Throwable -> L6f
            r0 = 0
            com.google.android.gms.internal.mlkit_vision_camera.AbstractC3344h.b(r6, r0)     // Catch: java.lang.Throwable -> L6d
            r1.c()
            return r3
        L6d:
            r6 = move-exception
            goto L76
        L6f:
            r0 = move-exception
            throw r0     // Catch: java.lang.Throwable -> L71
        L71:
            r2 = move-exception
            com.google.android.gms.internal.mlkit_vision_camera.AbstractC3344h.b(r6, r0)     // Catch: java.lang.Throwable -> L6d
            throw r2     // Catch: java.lang.Throwable -> L6d
        L76:
            r1.c()
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.decode.x.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
