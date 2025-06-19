package com.bumptech.glide.load.resource.bitmap;

import android.content.Context;
import android.graphics.Bitmap;
import com.bumptech.glide.Glide;

/* renamed from: com.bumptech.glide.load.resource.bitmap.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1542e implements com.bumptech.glide.load.l {
    @Override // com.bumptech.glide.load.l
    public final com.bumptech.glide.load.engine.v b(Context context, com.bumptech.glide.load.engine.v vVar, int i, int i2) {
        if (!com.bumptech.glide.util.m.i(i, i2)) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.j("Cannot apply transformation on width: ", i, " or height: ", " less than or equal to zero and not Target.SIZE_ORIGINAL", i2));
        }
        com.bumptech.glide.load.engine.bitmap_recycle.a aVar = Glide.a(context).a;
        Bitmap bitmap = (Bitmap) vVar.get();
        if (i == Integer.MIN_VALUE) {
            i = bitmap.getWidth();
        }
        if (i2 == Integer.MIN_VALUE) {
            i2 = bitmap.getHeight();
        }
        Bitmap bitmapC = c(aVar, bitmap, i, i2);
        return bitmap.equals(bitmapC) ? vVar : C1541d.d(bitmapC, aVar);
    }

    public abstract Bitmap c(com.bumptech.glide.load.engine.bitmap_recycle.a aVar, Bitmap bitmap, int i, int i2);
}
