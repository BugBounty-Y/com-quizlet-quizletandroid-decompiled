package com.google.android.gms.internal.ads;

import android.text.TextUtils;

/* renamed from: com.google.android.gms.internal.ads.x3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2812x3 {
    public final String a;
    public final String b;

    public C2812x3(String str, String str2) {
        this.a = str;
        this.b = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C2812x3.class == obj.getClass()) {
            C2812x3 c2812x3 = (C2812x3) obj;
            if (TextUtils.equals(this.a, c2812x3.a) && TextUtils.equals(this.b, c2812x3.b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Header[name=");
        sb.append(this.a);
        sb.append(",value=");
        return android.support.v4.media.session.a.t(sb, this.b, "]");
    }
}
