package com.bumptech.glide.load.resource.bitmap;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;

/* renamed from: com.bumptech.glide.load.resource.bitmap.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1541d implements com.bumptech.glide.load.engine.v, com.bumptech.glide.load.engine.s {
    public final /* synthetic */ int a = 1;
    public final Object b;
    public final Object c;

    public C1541d(Bitmap bitmap, com.bumptech.glide.load.engine.bitmap_recycle.a aVar) {
        com.bumptech.glide.util.f.c(bitmap, "Bitmap must not be null");
        this.b = bitmap;
        com.bumptech.glide.util.f.c(aVar, "BitmapPool must not be null");
        this.c = aVar;
    }

    public static C1541d d(Bitmap bitmap, com.bumptech.glide.load.engine.bitmap_recycle.a aVar) {
        if (bitmap == null) {
            return null;
        }
        return new C1541d(bitmap, aVar);
    }

    @Override // com.bumptech.glide.load.engine.v
    public final int a() {
        switch (this.a) {
            case 0:
                return com.bumptech.glide.util.m.c((Bitmap) this.b);
            default:
                return ((com.bumptech.glide.load.engine.v) this.c).a();
        }
    }

    @Override // com.bumptech.glide.load.engine.s
    public final void b() {
        switch (this.a) {
            case 0:
                ((Bitmap) this.b).prepareToDraw();
                break;
            default:
                com.bumptech.glide.load.engine.v vVar = (com.bumptech.glide.load.engine.v) this.c;
                if (vVar instanceof com.bumptech.glide.load.engine.s) {
                    ((com.bumptech.glide.load.engine.s) vVar).b();
                    break;
                }
                break;
        }
    }

    @Override // com.bumptech.glide.load.engine.v
    public final Class c() {
        switch (this.a) {
            case 0:
                return Bitmap.class;
            default:
                return BitmapDrawable.class;
        }
    }

    @Override // com.bumptech.glide.load.engine.v
    public final Object get() {
        switch (this.a) {
            case 0:
                return (Bitmap) this.b;
            default:
                return new BitmapDrawable((Resources) this.b, (Bitmap) ((com.bumptech.glide.load.engine.v) this.c).get());
        }
    }

    @Override // com.bumptech.glide.load.engine.v
    public final void recycle() {
        switch (this.a) {
            case 0:
                ((com.bumptech.glide.load.engine.bitmap_recycle.a) this.c).b((Bitmap) this.b);
                break;
            default:
                ((com.bumptech.glide.load.engine.v) this.c).recycle();
                break;
        }
    }

    public C1541d(Resources resources, com.bumptech.glide.load.engine.v vVar) {
        com.bumptech.glide.util.f.c(resources, "Argument must not be null");
        this.b = resources;
        com.bumptech.glide.util.f.c(vVar, "Argument must not be null");
        this.c = vVar;
    }
}
