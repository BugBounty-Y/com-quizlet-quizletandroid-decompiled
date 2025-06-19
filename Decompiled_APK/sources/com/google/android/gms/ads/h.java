package com.google.android.gms.ads;

import androidx.compose.ui.node.B;
import com.amazon.device.ads.DtbConstants;

/* loaded from: classes2.dex */
public final class h {
    public static final h i = new h(DtbConstants.DEFAULT_PLAYER_WIDTH, 50, "320x50_mb");
    public static final h j = new h(468, 60, "468x60_as");
    public static final h k = new h(DtbConstants.DEFAULT_PLAYER_WIDTH, 100, "320x100_as");
    public static final h l = new h(728, 90, "728x90_as");
    public static final h m = new h(300, 250, "300x250_as");
    public static final h n = new h(160, com.pubmatic.sdk.video.a.GENERAL_COMPANION_AD_ERROR, "160x600_as");
    public static final h o = new h(-1, -2, "smart_banner");
    public static final h p = new h(-3, -4, "fluid");
    public static final h q = new h(0, 0, "invalid");
    public static final h r = new h(50, 50, "50x50_mb");
    public final int a;
    public final int b;
    public final String c;
    public boolean d;
    public boolean e;
    public int f;
    public boolean g;
    public int h;

    static {
        new h(-3, 0, "search_v2");
    }

    public h(int i2, int i3) {
        this(i2, i3, B.i(i2 == -1 ? "FULL" : String.valueOf(i2), "x", i3 == -2 ? "AUTO" : String.valueOf(i3), "_as"));
    }

    public final boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.a == hVar.a && this.b == hVar.b && this.c.equals(hVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode();
    }

    public final String toString() {
        return this.c;
    }

    public h(int i2, int i3, String str) {
        if (i2 < 0 && i2 != -1 && i2 != -3) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "Invalid width for AdSize: "));
        }
        if (i3 < 0 && i3 != -2 && i3 != -4) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i3, "Invalid height for AdSize: "));
        }
        this.a = i2;
        this.b = i3;
        this.c = str;
    }
}
