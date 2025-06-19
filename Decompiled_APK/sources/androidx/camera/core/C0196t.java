package androidx.camera.core;

/* renamed from: androidx.camera.core.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0196t {
    public static final C0196t c = new C0196t(0, 0);
    public static final C0196t d = new C0196t(1, 8);
    public static final C0196t e = new C0196t(3, 10);
    public static final C0196t f = new C0196t(4, 10);
    public static final C0196t g = new C0196t(5, 10);
    public static final C0196t h = new C0196t(6, 10);
    public static final C0196t i = new C0196t(6, 8);
    public final int a;
    public final int b;

    public C0196t(int i2, int i3) {
        this.a = i2;
        this.b = i3;
    }

    public final boolean a() {
        return b() && this.a != 1 && this.b == 10;
    }

    public final boolean b() {
        int i2 = this.a;
        return (i2 == 0 || i2 == 2 || this.b == 0) ? false : true;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C0196t) {
            C0196t c0196t = (C0196t) obj;
            if (this.a == c0196t.a && this.b == c0196t.b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((this.a ^ 1000003) * 1000003) ^ this.b;
    }

    public final String toString() {
        String str;
        StringBuilder sb = new StringBuilder("DynamicRange@");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append("{encoding=");
        switch (this.a) {
            case 0:
                str = "UNSPECIFIED";
                break;
            case 1:
                str = "SDR";
                break;
            case 2:
                str = "HDR_UNSPECIFIED";
                break;
            case 3:
                str = "HLG";
                break;
            case 4:
                str = "HDR10";
                break;
            case 5:
                str = "HDR10_PLUS";
                break;
            case 6:
                str = "DOLBY_VISION";
                break;
            default:
                str = "<Unknown>";
                break;
        }
        sb.append(str);
        sb.append(", bitDepth=");
        return android.support.v4.media.session.a.r(sb, this.b, "}");
    }
}
