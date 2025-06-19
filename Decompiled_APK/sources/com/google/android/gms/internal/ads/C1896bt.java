package com.google.android.gms.internal.ads;

import android.os.IBinder;

/* renamed from: com.google.android.gms.internal.ads.bt, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1896bt {
    public final IBinder a;
    public final String b;
    public final int c;
    public final float d;
    public final int e;
    public final String f;

    public C1896bt(IBinder iBinder, String str, int i, float f, int i2, String str2) {
        this.a = iBinder;
        this.b = str;
        this.c = i;
        this.d = f;
        this.e = i2;
        this.f = str2;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C1896bt) {
            C1896bt c1896bt = (C1896bt) obj;
            if (this.a.equals(c1896bt.a)) {
                String str = c1896bt.b;
                String str2 = this.b;
                if (str2 != null ? str2.equals(str) : str == null) {
                    if (this.c == c1896bt.c && Float.floatToIntBits(this.d) == Float.floatToIntBits(c1896bt.d) && this.e == c1896bt.e) {
                        String str3 = c1896bt.f;
                        String str4 = this.f;
                        if (str4 != null ? str4.equals(str3) : str3 == null) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() ^ 1000003;
        String str = this.b;
        int iHashCode2 = (((((iHashCode * 1000003) ^ (str == null ? 0 : str.hashCode())) * 1000003) ^ this.c) * 1000003) ^ Float.floatToIntBits(this.d);
        String str2 = this.f;
        return ((((iHashCode2 * 1525764945) ^ this.e) * (-721379959)) ^ (str2 != null ? str2.hashCode() : 0)) * 1000003;
    }

    public final String toString() {
        StringBuilder sbY = android.support.v4.media.session.a.y("OverlayDisplayShowRequest{windowToken=", this.a.toString(), ", appId=");
        sbY.append(this.b);
        sbY.append(", layoutGravity=");
        sbY.append(this.c);
        sbY.append(", layoutVerticalMargin=");
        sbY.append(this.d);
        sbY.append(", displayMode=0, triggerMode=0, sessionToken=null, windowWidthPx=");
        sbY.append(this.e);
        sbY.append(", deeplinkUrl=null, adFieldEnifd=");
        return android.support.v4.media.session.a.t(sbY, this.f, ", thirdPartyAuthCallerId=null}");
    }
}
