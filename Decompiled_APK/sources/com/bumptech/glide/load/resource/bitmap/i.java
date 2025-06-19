package com.bumptech.glide.load.resource.bitmap;

import android.graphics.Bitmap;
import android.graphics.Paint;
import android.util.Log;
import java.security.MessageDigest;

/* loaded from: classes.dex */
public final class i extends AbstractC1542e {
    public static final byte[] b = "com.bumptech.glide.load.resource.bitmap.CenterInside".getBytes(com.bumptech.glide.load.e.a);

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        messageDigest.update(b);
    }

    @Override // com.bumptech.glide.load.resource.bitmap.AbstractC1542e
    public final Bitmap c(com.bumptech.glide.load.engine.bitmap_recycle.a aVar, Bitmap bitmap, int i, int i2) {
        Paint paint = z.a;
        if (bitmap.getWidth() > i || bitmap.getHeight() > i2) {
            Log.isLoggable("TransformationUtils", 2);
            return z.b(aVar, bitmap, i, i2);
        }
        Log.isLoggable("TransformationUtils", 2);
        return bitmap;
    }

    @Override // com.bumptech.glide.load.e
    public final boolean equals(Object obj) {
        return obj instanceof i;
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        return -670243078;
    }
}
