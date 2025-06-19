package com.bumptech.glide.load.resource.bitmap;

import android.graphics.Bitmap;
import android.graphics.ImageDecoder;
import android.util.Log;
import java.io.IOException;

/* renamed from: com.bumptech.glide.load.resource.bitmap.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1540c implements com.bumptech.glide.load.j {
    public final /* synthetic */ int a;
    public final com.bumptech.glide.load.engine.bitmap_recycle.a b;

    public C1540c() {
        this.a = 0;
        this.b = new com.google.mlkit.common.internal.model.a(6);
    }

    @Override // com.bumptech.glide.load.j
    public final /* bridge */ /* synthetic */ boolean a(Object obj, com.bumptech.glide.load.h hVar) {
        switch (this.a) {
            case 0:
                com.bumptech.glide.load.resource.a.t(obj);
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
                return c(com.bumptech.glide.load.resource.a.j(obj), i, i2, hVar);
            default:
                return C1541d.d(((com.bumptech.glide.gifdecoder.d) obj).b(), this.b);
        }
    }

    public C1541d c(ImageDecoder.Source source, int i, int i2, com.bumptech.glide.load.h hVar) throws IOException {
        Bitmap bitmapDecodeBitmap = ImageDecoder.decodeBitmap(source, new com.bumptech.glide.load.resource.c(i, i2, hVar));
        if (Log.isLoggable("BitmapImageDecoder", 2)) {
            bitmapDecodeBitmap.getWidth();
            bitmapDecodeBitmap.getHeight();
        }
        return new C1541d(bitmapDecodeBitmap, (com.google.mlkit.common.internal.model.a) this.b);
    }

    public C1540c(com.bumptech.glide.load.engine.bitmap_recycle.a aVar) {
        this.a = 1;
        this.b = aVar;
    }
}
