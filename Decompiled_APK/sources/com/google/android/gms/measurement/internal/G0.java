package com.google.android.gms.measurement.internal;

import android.graphics.Bitmap;
import java.io.File;
import java.io.IOException;
import java.util.Map;

/* loaded from: classes2.dex */
public final /* synthetic */ class G0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ G0(int i, int i2, Object obj, Object obj2, Object obj3) {
        this.a = i2;
        this.c = obj;
        this.b = i;
        this.d = obj2;
        this.e = obj3;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:32:0x008e A[Catch: all -> 0x008a, TryCatch #0 {all -> 0x008a, blocks: (B:19:0x004d, B:21:0x0069, B:23:0x006f, B:25:0x0075, B:28:0x0084, B:32:0x008e, B:36:0x0098, B:39:0x00a2, B:40:0x00ad), top: B:55:0x004d }] */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0098 A[Catch: all -> 0x008a, PHI: r3
  0x0098: PHI (r3v8 android.net.Uri) = (r3v17 android.net.Uri), (r3v10 android.net.Uri) binds: [B:31:0x008c, B:35:0x0097] A[DONT_GENERATE, DONT_INLINE], TRY_LEAVE, TryCatch #0 {all -> 0x008a, blocks: (B:19:0x004d, B:21:0x0069, B:23:0x006f, B:25:0x0075, B:28:0x0084, B:32:0x008e, B:36:0x0098, B:39:0x00a2, B:40:0x00ad), top: B:55:0x004d }] */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 286
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.G0.run():void");
    }

    public /* synthetic */ G0(L l, int i, IOException iOException, byte[] bArr, Map map) {
        this.a = 0;
        this.c = l;
        this.b = i;
        this.d = iOException;
        this.e = bArr;
    }

    public G0(File file, Bitmap bitmap, Bitmap.CompressFormat compressFormat, int i) {
        this.a = 3;
        this.c = file;
        this.d = bitmap;
        this.e = compressFormat;
        this.b = i;
    }
}
