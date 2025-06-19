package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.SystemClock;
import android.text.TextUtils;

/* loaded from: classes2.dex */
public final class zzik extends zzba {
    public final int c;
    public final String d;
    public final int e;
    public final C1832aG f;
    public final int g;
    public final C2093gF h;
    public final boolean i;

    public zzik(int i, Exception exc, int i2) {
        this(i, exc, i2, null, -1, null, 4, null, false);
    }

    public final zzik a(C2093gF c2093gF) {
        String message = getMessage();
        String str = Yo.a;
        return new zzik(message, getCause(), this.a, this.c, this.d, this.e, this.f, this.g, c2093gF, this.b, this.i);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public zzik(int i, Exception exc, int i2, String str, int i3, C1832aG c1832aG, int i4, C2093gF c2093gF, boolean z) {
        String str2;
        int i5;
        String strT;
        String str3;
        if (i == 0) {
            str2 = str;
            i5 = i3;
            strT = "Source error";
        } else if (i != 1) {
            strT = "Unexpected runtime error";
            str2 = str;
            i5 = i3;
        } else {
            String strValueOf = String.valueOf(c1832aG);
            String str4 = Yo.a;
            if (i4 == 0) {
                str3 = "NO";
            } else if (i4 == 1) {
                str3 = "NO_UNSUPPORTED_TYPE";
            } else if (i4 == 2) {
                str3 = "NO_UNSUPPORTED_DRM";
            } else if (i4 == 3) {
                str3 = "NO_EXCEEDS_CAPABILITIES";
            } else {
                if (i4 != 4) {
                    throw new IllegalStateException();
                }
                str3 = "YES";
            }
            StringBuilder sb = new StringBuilder();
            str2 = str;
            sb.append(str2);
            sb.append(" error, index=");
            i5 = i3;
            sb.append(i5);
            sb.append(", format=");
            sb.append(strValueOf);
            strT = android.support.v4.media.session.a.t(sb, ", format_supported=", str3);
        }
        this(TextUtils.isEmpty(null) ? strT : strT.concat(": null"), exc, i2, i, str2, i5, c1832aG, i4, c2093gF, SystemClock.elapsedRealtime(), z);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public zzik(String str, Throwable th, int i, int i2, String str2, int i3, C1832aG c1832aG, int i4, C2093gF c2093gF, long j, boolean z) {
        int i5;
        boolean z2;
        super(str, th, i, j);
        Bundle bundle = Bundle.EMPTY;
        if (!z) {
            i5 = i2;
            z2 = true;
        } else if (i2 == 1) {
            i5 = 1;
            z2 = true;
        } else {
            i5 = i2;
            z2 = false;
        }
        AbstractC1795We.B(z2);
        AbstractC1795We.B(th != null);
        this.c = i5;
        this.d = str2;
        this.e = i3;
        this.f = c1832aG;
        this.g = i4;
        this.h = c2093gF;
        this.i = z;
    }
}
