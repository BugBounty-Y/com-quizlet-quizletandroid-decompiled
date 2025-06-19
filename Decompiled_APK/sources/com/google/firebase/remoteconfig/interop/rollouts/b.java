package com.google.firebase.remoteconfig.interop.rollouts;

import com.google.android.gms.measurement.internal.Z;

/* loaded from: classes2.dex */
public final class b {
    public String a;
    public String b;
    public String c;
    public String d;
    public long e;
    public byte f;

    public final c a() {
        if (this.f == 1 && this.a != null && this.b != null && this.c != null && this.d != null) {
            return new c(this.a, this.b, this.c, this.d, this.e);
        }
        StringBuilder sb = new StringBuilder();
        if (this.a == null) {
            sb.append(" rolloutId");
        }
        if (this.b == null) {
            sb.append(" variantId");
        }
        if (this.c == null) {
            sb.append(" parameterKey");
        }
        if (this.d == null) {
            sb.append(" parameterValue");
        }
        if ((1 & this.f) == 0) {
            sb.append(" templateVersion");
        }
        throw new IllegalStateException(Z.i("Missing required properties:", sb));
    }
}
