package com.google.android.gms.internal.ads;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Looper;

/* renamed from: com.google.android.gms.internal.ads.zj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2920zj {
    public final com.google.android.gms.ads.internal.util.q a;
    public final com.google.android.gms.common.util.a b;
    public final Xv c;

    public C2920zj(com.google.android.gms.ads.internal.util.q qVar, com.google.android.gms.common.util.a aVar, Xv xv) {
        this.a = qVar;
        this.b = aVar;
        this.c = xv;
    }

    public final Bitmap a(byte[] bArr, BitmapFactory.Options options) {
        com.google.android.gms.common.util.a aVar = this.b;
        long jElapsedRealtime = aVar.elapsedRealtime();
        Bitmap bitmapDecodeByteArray = BitmapFactory.decodeByteArray(bArr, 0, bArr.length, options);
        long jElapsedRealtime2 = aVar.elapsedRealtime();
        if (bitmapDecodeByteArray != null) {
            long j = jElapsedRealtime2 - jElapsedRealtime;
            int width = bitmapDecodeByteArray.getWidth();
            int height = bitmapDecodeByteArray.getHeight();
            int allocationByteCount = bitmapDecodeByteArray.getAllocationByteCount();
            boolean z = Looper.getMainLooper().getThread() == Thread.currentThread();
            StringBuilder sbW = android.support.v4.media.session.a.w("Decoded image w: ", width, " h:", " bytes: ", height);
            sbW.append(allocationByteCount);
            sbW.append(" time: ");
            sbW.append(j);
            sbW.append(" on ui thread: ");
            sbW.append(z);
            com.google.android.gms.ads.internal.util.A.l(sbW.toString());
        }
        return bitmapDecodeByteArray;
    }
}
