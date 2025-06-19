package com.lyft.android.scissors;

import android.graphics.Bitmap;
import android.graphics.Rect;
import com.bumptech.glide.load.resource.bitmap.AbstractC1542e;
import java.nio.charset.Charset;
import java.security.MessageDigest;

/* loaded from: classes2.dex */
public final class g extends AbstractC1542e {
    public static final byte[] d = "com.lyft.android.scissors.GlideFillViewportTransformation".getBytes(Charset.defaultCharset());
    public final int b;
    public final int c;

    public g(int i, int i2) {
        this.b = i;
        this.c = i2;
    }

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        messageDigest.update(d);
    }

    @Override // com.bumptech.glide.load.resource.bitmap.AbstractC1542e
    public final Bitmap c(com.bumptech.glide.load.engine.bitmap_recycle.a aVar, Bitmap bitmap, int i, int i2) {
        float f;
        float f2;
        Rect rect;
        int width = bitmap.getWidth();
        int height = bitmap.getHeight();
        boolean z = f.a;
        int i3 = this.b;
        int i4 = this.c;
        if (width == i3 && height == i4) {
            rect = new Rect(0, 0, i3, i4);
        } else {
            if (width * i4 > i3 * height) {
                f = i4;
                f2 = height;
            } else {
                f = i3;
                f2 = width;
            }
            float f3 = f / f2;
            rect = new Rect(0, 0, (int) ((width * f3) + 0.5f), (int) ((height * f3) + 0.5f));
        }
        return Bitmap.createScaledBitmap(bitmap, rect.width(), rect.height(), true);
    }

    @Override // com.bumptech.glide.load.e
    public final boolean equals(Object obj) {
        if (obj instanceof g) {
            g gVar = (g) obj;
            if (gVar.b == this.b && gVar.c == this.c) {
                return true;
            }
        }
        return false;
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        return (((this.b * 31) + this.c) * 17) - 518388059;
    }
}
