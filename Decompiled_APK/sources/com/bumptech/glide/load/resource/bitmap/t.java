package com.bumptech.glide.load.resource.bitmap;

import android.graphics.Bitmap;
import java.security.MessageDigest;

/* loaded from: classes.dex */
public final class t extends AbstractC1542e {
    public static final byte[] b = "com.bumptech.glide.load.resource.bitmap.FitCenter".getBytes(com.bumptech.glide.load.e.a);

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        messageDigest.update(b);
    }

    @Override // com.bumptech.glide.load.resource.bitmap.AbstractC1542e
    public final Bitmap c(com.bumptech.glide.load.engine.bitmap_recycle.a aVar, Bitmap bitmap, int i, int i2) {
        return z.b(aVar, bitmap, i, i2);
    }

    @Override // com.bumptech.glide.load.e
    public final boolean equals(Object obj) {
        return obj instanceof t;
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        return 1572326941;
    }
}
