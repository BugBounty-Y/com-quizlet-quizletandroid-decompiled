package com.bumptech.glide.load.resource.bitmap;

/* loaded from: classes.dex */
public final class m {
    public static final m b = new m(2);
    public static final m c = new m(0);
    public static final m d;
    public static final m e;
    public static final m f;
    public static final com.bumptech.glide.load.g g;
    public static final boolean h;
    public final /* synthetic */ int a;

    static {
        m mVar = new m(1);
        d = mVar;
        e = new m(3);
        f = mVar;
        g = com.bumptech.glide.load.g.a(mVar, "com.bumptech.glide.load.resource.bitmap.Downsampler.DownsampleStrategy");
        h = true;
    }

    public /* synthetic */ m(int i) {
        this.a = i;
    }

    public final int a(int i, int i2, int i3, int i4) {
        switch (this.a) {
            case 0:
                if (b(i, i2, i3, i4) != 1.0f) {
                    break;
                }
                break;
            case 2:
                if (h) {
                }
                break;
        }
        return 2;
    }

    public final float b(int i, int i2, int i3, int i4) {
        switch (this.a) {
            case 0:
                return Math.min(1.0f, b.b(i, i2, i3, i4));
            case 1:
                return Math.max(i3 / i, i4 / i2);
            case 2:
                if (h) {
                    return Math.min(i3 / i, i4 / i2);
                }
                if (Math.max(i2 / i4, i / i3) == 0) {
                    return 1.0f;
                }
                return 1.0f / Integer.highestOneBit(r2);
            default:
                return 1.0f;
        }
    }
}
