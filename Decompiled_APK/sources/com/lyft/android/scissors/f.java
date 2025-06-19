package com.lyft.android.scissors;

/* loaded from: classes2.dex */
public abstract class f {
    public static final boolean a;
    public static final boolean b;
    public static final boolean c;

    static {
        boolean z;
        boolean z2 = false;
        try {
            Class.forName("com.squareup.picasso.Picasso");
            z = true;
        } catch (ClassNotFoundException unused) {
            z = false;
        }
        a = z;
        b = true;
        try {
            Class.forName("com.nostra13.universalimageloader.core.ImageLoader");
            z2 = true;
        } catch (ClassNotFoundException unused2) {
        }
        c = z2;
    }
}
