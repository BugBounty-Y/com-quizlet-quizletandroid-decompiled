package com.bumptech.glide.load.resource.bitmap;

import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.RectF;
import android.graphics.Shader;
import com.skydoves.balloon.internals.DefinitionKt;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.concurrent.locks.Lock;

/* loaded from: classes.dex */
public final class x extends AbstractC1542e {
    public static final byte[] c = "com.bumptech.glide.load.resource.bitmap.RoundedCorners".getBytes(com.bumptech.glide.load.e.a);
    public final int b;

    public x(int i) {
        com.bumptech.glide.util.f.a("roundingRadius must be greater than 0.", i > 0);
        this.b = i;
    }

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        messageDigest.update(c);
        messageDigest.update(ByteBuffer.allocate(4).putInt(this.b).array());
    }

    @Override // com.bumptech.glide.load.resource.bitmap.AbstractC1542e
    public final Bitmap c(com.bumptech.glide.load.engine.bitmap_recycle.a aVar, Bitmap bitmap, int i, int i2) {
        Paint paint = z.a;
        int i3 = this.b;
        com.bumptech.glide.util.f.a("roundingRadius must be greater than 0.", i3 > 0);
        Bitmap.Config config = Bitmap.Config.RGBA_F16;
        if (!config.equals(bitmap.getConfig())) {
            config = Bitmap.Config.ARGB_8888;
        }
        Bitmap bitmapC = z.c(bitmap, aVar);
        Bitmap bitmapC2 = aVar.c(bitmapC.getWidth(), bitmapC.getHeight(), config);
        bitmapC2.setHasAlpha(true);
        Shader.TileMode tileMode = Shader.TileMode.CLAMP;
        BitmapShader bitmapShader = new BitmapShader(bitmapC, tileMode, tileMode);
        Paint paint2 = new Paint();
        paint2.setAntiAlias(true);
        paint2.setShader(bitmapShader);
        RectF rectF = new RectF(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, bitmapC2.getWidth(), bitmapC2.getHeight());
        Lock lock = z.d;
        lock.lock();
        try {
            Canvas canvas = new Canvas(bitmapC2);
            canvas.drawColor(0, PorterDuff.Mode.CLEAR);
            float f = i3;
            canvas.drawRoundRect(rectF, f, f, paint2);
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
        return (obj instanceof x) && this.b == ((x) obj).b;
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        return com.bumptech.glide.util.m.g(-569625254, com.bumptech.glide.util.m.g(this.b, 17));
    }
}
