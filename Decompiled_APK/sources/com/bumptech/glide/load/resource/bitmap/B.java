package com.bumptech.glide.load.resource.bitmap;

import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import java.io.File;

/* loaded from: classes.dex */
public final class B implements com.bumptech.glide.load.j {
    public final /* synthetic */ int a;

    @Override // com.bumptech.glide.load.j
    public final /* bridge */ /* synthetic */ boolean a(Object obj, com.bumptech.glide.load.h hVar) {
        switch (this.a) {
            case 0:
                break;
            case 1:
                break;
            default:
                break;
        }
        return true;
    }

    @Override // com.bumptech.glide.load.j
    public final com.bumptech.glide.load.engine.v b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) {
        switch (this.a) {
            case 0:
                return new A((Bitmap) obj, 0);
            case 1:
                Drawable drawable = (Drawable) obj;
                if (drawable != null) {
                    return new com.bumptech.glide.load.resource.drawable.b(drawable, 0);
                }
                return null;
            default:
                return new A((File) obj);
        }
    }
}
