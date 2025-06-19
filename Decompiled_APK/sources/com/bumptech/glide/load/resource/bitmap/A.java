package com.bumptech.glide.load.resource.bitmap;

import android.graphics.Bitmap;
import android.graphics.drawable.AnimatedImageDrawable;
import android.graphics.drawable.Drawable;
import java.io.File;

/* loaded from: classes.dex */
public final class A implements com.bumptech.glide.load.engine.v {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ A(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void b() {
    }

    private final void d() {
    }

    private final void e() {
    }

    @Override // com.bumptech.glide.load.engine.v
    public final int a() {
        switch (this.a) {
            case 0:
                return com.bumptech.glide.util.m.c((Bitmap) this.b);
            case 1:
                return ((byte[]) this.b).length;
            case 2:
                return com.bumptech.glide.util.m.d(Bitmap.Config.ARGB_8888) * ((AnimatedImageDrawable) this.b).getIntrinsicHeight() * ((AnimatedImageDrawable) this.b).getIntrinsicWidth() * 2;
            default:
                return 1;
        }
    }

    @Override // com.bumptech.glide.load.engine.v
    public final Class c() {
        switch (this.a) {
            case 0:
                return Bitmap.class;
            case 1:
                return byte[].class;
            case 2:
                return Drawable.class;
            default:
                return ((File) this.b).getClass();
        }
    }

    @Override // com.bumptech.glide.load.engine.v
    public final Object get() {
        switch (this.a) {
            case 0:
                return (Bitmap) this.b;
            case 1:
                return (byte[]) this.b;
            case 2:
                return (AnimatedImageDrawable) this.b;
            default:
                return (File) this.b;
        }
    }

    @Override // com.bumptech.glide.load.engine.v
    public final void recycle() {
        switch (this.a) {
            case 2:
                ((AnimatedImageDrawable) this.b).stop();
                ((AnimatedImageDrawable) this.b).clearAnimationCallbacks();
                break;
        }
    }

    public A(byte[] bArr) {
        this.a = 1;
        com.bumptech.glide.util.f.c(bArr, "Argument must not be null");
        this.b = bArr;
    }

    public A(File file) {
        this.a = 3;
        com.bumptech.glide.util.f.c(file, "Argument must not be null");
        this.b = file;
    }
}
