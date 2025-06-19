package com.google.android.gms.internal.ads;

import android.text.TextUtils;

/* loaded from: classes2.dex */
public final class KE {
    public final String a;
    public final boolean b;
    public final boolean c;

    public KE(String str, boolean z, boolean z2) {
        this.a = str;
        this.b = z;
        this.c = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || obj.getClass() != KE.class) {
            return false;
        }
        KE ke = (KE) obj;
        return TextUtils.equals(this.a, ke.a) && this.b == ke.b && this.c == ke.c;
    }

    public final int hashCode() {
        return ((((this.a.hashCode() + 31) * 31) + (true != this.b ? 1237 : 1231)) * 31) + (true != this.c ? 1237 : 1231);
    }
}
