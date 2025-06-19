package com.google.android.gms.internal.ads;

import android.text.TextUtils;

/* loaded from: classes2.dex */
public final class RC {
    public final String a;
    public final C1832aG b;
    public final C1832aG c;
    public final int d;
    public final int e;

    public RC(String str, C1832aG c1832aG, C1832aG c1832aG2, int i, int i2) {
        boolean z = true;
        if (i != 0) {
            if (i2 == 0) {
                i2 = 0;
            } else {
                z = false;
            }
        }
        AbstractC1795We.B(z);
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException();
        }
        this.a = str;
        this.b = c1832aG;
        c1832aG2.getClass();
        this.c = c1832aG2;
        this.d = i;
        this.e = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && RC.class == obj.getClass()) {
            RC rc = (RC) obj;
            if (this.d == rc.d && this.e == rc.e && this.a.equals(rc.a) && this.b.equals(rc.b) && this.c.equals(rc.c)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + ((this.a.hashCode() + ((((this.d + 527) * 31) + this.e) * 31)) * 31)) * 31);
    }
}
