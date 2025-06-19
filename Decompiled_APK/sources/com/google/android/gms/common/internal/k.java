package com.google.android.gms.common.internal;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class k implements com.google.android.gms.common.api.b {
    public static final k b = new k(null);
    public final String a;

    public /* synthetic */ k(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof k) {
            return u.l(this.a, ((k) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a});
    }
}
