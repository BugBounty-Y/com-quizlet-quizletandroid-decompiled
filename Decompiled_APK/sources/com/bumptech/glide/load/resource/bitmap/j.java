package com.bumptech.glide.load.resource.bitmap;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import java.security.MessageDigest;
import java.util.concurrent.locks.Lock;

/* loaded from: classes.dex */
public final class j extends AbstractC1542e {
    public static final byte[] b = "com.bumptech.glide.load.resource.bitmap.CircleCrop.1".getBytes(com.bumptech.glide.load.e.a);

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        messageDigest.update(b);
    }

    @Override // com.bumptech.glide.load.resource.bitmap.AbstractC1542e
    public final Bitmap c(com.bumptech.glide.load.engine.bitmap_recycle.a aVar, Bitmap bitmap, int i, int i2) {
        Paint paint = z.a;
        int iMin = Math.min(i, i2);
        float f = iMin;
        float f2 = f / 2.0f;
        float width = bitmap.getWidth();
        float height = bitmap.getHeight();
        float fMax = Math.max(f / width, f / height);
        float f3 = width * fMax;
        float f4 = fMax * height;
        float f5 = (f - f3) / 2.0f;
        float f6 = (f - f4) / 2.0f;
        RectF rectF = new RectF(f5, f6, f3 + f5, f4 + f6);
        Bitmap bitmapC = z.c(bitmap, aVar);
        Bitmap.Config config = Bitmap.Config.RGBA_F16;
        if (!config.equals(bitmap.getConfig())) {
            config = Bitmap.Config.ARGB_8888;
        }
        Bitmap bitmapC2 = aVar.c(iMin, iMin, config);
        bitmapC2.setHasAlpha(true);
        Lock lock = z.d;
        lock.lock();
        try {
            Canvas canvas = new Canvas(bitmapC2);
            canvas.drawCircle(f2, f2, f2, z.b);
            canvas.drawBitmap(bitmapC, (Rect) null, rectF, z.c);
            canvas.setBitmap(null);
            lock.unlock();
            if (!bitmapC.equals(bitmap)) {
                aVar.b(bitmapC);
            }
            return bitmapC2;
        } catch (Throwable th) {
            lock.unlock();
            throw th;
        }
    }

    @Override // com.bumptech.glide.load.e
    public final boolean equals(Object obj) {
        return obj instanceof j;
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        return 1101716364;
    }
}
