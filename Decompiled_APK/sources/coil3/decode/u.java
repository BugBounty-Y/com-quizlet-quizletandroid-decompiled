package coil3.decode;

/* loaded from: classes.dex */
public final class u implements j {
    public final kotlinx.coroutines.sync.i a;

    public u(kotlinx.coroutines.sync.i iVar) {
        this.a = iVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0081  */
    @Override // coil3.decode.j
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final coil3.decode.k a(coil3.fetch.i r7, coil3.request.m r8) throws android.system.ErrnoException {
        /*
            r6 = this;
            android.graphics.Bitmap$Config r0 = coil3.request.i.a(r8)
            android.graphics.Bitmap$Config r1 = android.graphics.Bitmap.Config.ARGB_8888
            r2 = 0
            if (r0 == r1) goto Ld
            android.graphics.Bitmap$Config r1 = android.graphics.Bitmap.Config.HARDWARE
            if (r0 != r1) goto L91
        Ld:
            coil3.decode.q r0 = r7.a
            okio.n r1 = r0.V()
            okio.t r3 = okio.n.a
            if (r1 != r3) goto L26
            okio.x r1 = r0.W()
            if (r1 == 0) goto L26
            java.io.File r0 = r1.g()
            android.graphics.ImageDecoder$Source r0 = androidx.webkit.internal.f.f(r0)
            goto L8f
        L26:
            com.google.android.gms.internal.mlkit_vision_camera.t3 r0 = r0.getMetadata()
            boolean r1 = r0 instanceof coil3.decode.a
            android.content.Context r3 = r8.a
            if (r1 == 0) goto L3d
            android.content.res.AssetManager r1 = r3.getAssets()
            coil3.decode.a r0 = (coil3.decode.a) r0
            java.lang.String r0 = r0.a
            android.graphics.ImageDecoder$Source r0 = androidx.webkit.internal.f.d(r1, r0)
            goto L8f
        L3d:
            boolean r1 = r0 instanceof coil3.decode.g
            if (r1 == 0) goto L63
            int r1 = android.os.Build.VERSION.SDK_INT
            r4 = 29
            if (r1 < r4) goto L63
            coil3.decode.g r0 = (coil3.decode.g) r0     // Catch: android.system.ErrnoException -> L8e
            android.content.res.AssetFileDescriptor r0 = r0.a     // Catch: android.system.ErrnoException -> L8e
            java.io.FileDescriptor r1 = r0.getFileDescriptor()     // Catch: android.system.ErrnoException -> L8e
            long r3 = r0.getStartOffset()     // Catch: android.system.ErrnoException -> L8e
            int r5 = android.system.OsConstants.SEEK_SET     // Catch: android.system.ErrnoException -> L8e
            android.system.Os.lseek(r1, r3, r5)     // Catch: android.system.ErrnoException -> L8e
            androidx.work.impl.utils.d r1 = new androidx.work.impl.utils.d     // Catch: android.system.ErrnoException -> L8e
            r3 = 1
            r1.<init>(r0, r3)     // Catch: android.system.ErrnoException -> L8e
            android.graphics.ImageDecoder$Source r0 = androidx.core.view.o0.d(r1)     // Catch: android.system.ErrnoException -> L8e
            goto L8f
        L63:
            boolean r1 = r0 instanceof coil3.decode.r
            if (r1 == 0) goto L81
            r1 = r0
            coil3.decode.r r1 = (coil3.decode.r) r1
            java.lang.String r4 = r1.a
            java.lang.String r5 = r3.getPackageName()
            boolean r4 = r4.equals(r5)
            if (r4 == 0) goto L81
            android.content.res.Resources r0 = r3.getResources()
            int r1 = r1.b
            android.graphics.ImageDecoder$Source r0 = androidx.webkit.internal.f.e(r0, r1)
            goto L8f
        L81:
            boolean r1 = r0 instanceof coil3.decode.f
            if (r1 == 0) goto L8e
            coil3.decode.f r0 = (coil3.decode.f) r0
            java.nio.ByteBuffer r0 = r0.a
            android.graphics.ImageDecoder$Source r0 = androidx.webkit.internal.f.g(r0)
            goto L8f
        L8e:
            r0 = r2
        L8f:
            if (r0 != 0) goto L92
        L91:
            return r2
        L92:
            coil3.decode.x r1 = new coil3.decode.x
            kotlinx.coroutines.sync.i r2 = r6.a
            coil3.decode.q r7 = r7.a
            r1.<init>(r0, r7, r8, r2)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.decode.u.a(coil3.fetch.i, coil3.request.m):coil3.decode.k");
    }
}
