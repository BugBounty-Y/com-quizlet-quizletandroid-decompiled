package com.google.mlkit.vision.common;

import android.graphics.Bitmap;
import android.media.Image;
import com.google.android.gms.common.internal.u;
import com.google.firebase.platforminfo.c;

/* loaded from: classes2.dex */
public final class a {
    public volatile Bitmap a;
    public volatile c b;
    public final int c;
    public final int d;
    public final int e;
    public final int f;

    public a(Bitmap bitmap) {
        u.h(bitmap);
        this.a = bitmap;
        this.c = bitmap.getWidth();
        this.d = bitmap.getHeight();
        b(0);
        this.e = 0;
        this.f = -1;
    }

    public static void b(int i) {
        boolean z = true;
        if (i != 0 && i != 90 && i != 180 && i != 270) {
            z = false;
        }
        u.a("Invalid rotation. Only 0, 90, 180, 270 are supported currently.", z);
    }

    public final Image.Plane[] a() {
        if (this.b == null) {
            return null;
        }
        return ((Image) this.b.a).getPlanes();
    }

    public a(Image image, int i, int i2, int i3) {
        this.b = new c(image);
        this.c = i;
        this.d = i2;
        b(i3);
        this.e = i3;
        this.f = 35;
    }
}
