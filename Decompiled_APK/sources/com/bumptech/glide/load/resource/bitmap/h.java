package com.bumptech.glide.load.resource.bitmap;

import android.graphics.Bitmap;
import android.graphics.Matrix;
import android.graphics.Paint;
import com.skydoves.balloon.internals.DefinitionKt;
import java.security.MessageDigest;

/* loaded from: classes.dex */
public final class h extends AbstractC1542e {
    public static final byte[] b = "com.bumptech.glide.load.resource.bitmap.CenterCrop".getBytes(com.bumptech.glide.load.e.a);

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        messageDigest.update(b);
    }

    @Override // com.bumptech.glide.load.resource.bitmap.AbstractC1542e
    public final Bitmap c(com.bumptech.glide.load.engine.bitmap_recycle.a aVar, Bitmap bitmap, int i, int i2) {
        float width;
        float height;
        Paint paint = z.a;
        if (bitmap.getWidth() == i && bitmap.getHeight() == i2) {
            return bitmap;
        }
        Matrix matrix = new Matrix();
        int width2 = bitmap.getWidth() * i2;
        int height2 = bitmap.getHeight() * i;
        float width3 = DefinitionKt.NO_Float_VALUE;
        if (width2 > height2) {
            width = i2 / bitmap.getHeight();
            width3 = (i - (bitmap.getWidth() * width)) * 0.5f;
            height = 0.0f;
        } else {
            width = i / bitmap.getWidth();
            height = (i2 - (bitmap.getHeight() * width)) * 0.5f;
        }
        matrix.setScale(width, width);
        matrix.postTranslate((int) (width3 + 0.5f), (int) (height + 0.5f));
        Bitmap bitmapC = aVar.c(i, i2, bitmap.getConfig() != null ? bitmap.getConfig() : Bitmap.Config.ARGB_8888);
        bitmapC.setHasAlpha(bitmap.hasAlpha());
        z.a(bitmap, bitmapC, matrix);
        return bitmapC;
    }

    @Override // com.bumptech.glide.load.e
    public final boolean equals(Object obj) {
        return obj instanceof h;
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        return -599754482;
    }
}
