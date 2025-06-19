package com.google.android.gms.common.internal;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class B {
    public final String a;
    public final String b;
    public final boolean c;

    public B(String str, boolean z) {
        u.e(str);
        this.a = str;
        u.e("com.google.android.gms");
        this.b = "com.google.android.gms";
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof B)) {
            return false;
        }
        B b = (B) obj;
        return u.l(this.a, b.a) && u.l(this.b, b.b) && u.l(null, null) && this.c == b.c;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b, null, 4225, Boolean.valueOf(this.c)});
    }

    public final String toString() {
        String str = this.a;
        if (str != null) {
            return str;
        }
        u.h(null);
        throw null;
    }
}
