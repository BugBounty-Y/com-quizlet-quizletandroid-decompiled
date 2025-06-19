package com.google.android.gms.internal.ads;

import android.media.metrics.LogSessionId;
import android.os.Build;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.cE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1917cE {
    public final String a;
    public final Sq b;
    public final Object c;

    static {
        new C1917cE("");
    }

    public C1917cE(String str) {
        Sq sq;
        this.a = str;
        if (Build.VERSION.SDK_INT >= 31) {
            sq = new Sq();
            sq.a = LogSessionId.LOG_SESSION_ID_NONE;
        } else {
            sq = null;
        }
        this.b = sq;
        this.c = new Object();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1917cE)) {
            return false;
        }
        C1917cE c1917cE = (C1917cE) obj;
        return Objects.equals(this.a, c1917cE.a) && Objects.equals(this.b, c1917cE.b) && Objects.equals(this.c, c1917cE.c);
    }

    public final int hashCode() {
        return Objects.hash(this.a, this.b, this.c);
    }
}
