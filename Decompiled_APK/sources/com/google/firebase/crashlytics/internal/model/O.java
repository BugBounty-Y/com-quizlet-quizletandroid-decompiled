package com.google.firebase.crashlytics.internal.model;

/* loaded from: classes2.dex */
public final class O {
    public long a;
    public String b;
    public Q c;
    public C3929c0 d;
    public C3931d0 e;
    public C3939h0 f;
    public byte g;

    public final P a() {
        String str;
        Q q;
        C3929c0 c3929c0;
        if (this.g == 1 && (str = this.b) != null && (q = this.c) != null && (c3929c0 = this.d) != null) {
            return new P(this.a, str, q, c3929c0, this.e, this.f);
        }
        StringBuilder sb = new StringBuilder();
        if ((1 & this.g) == 0) {
            sb.append(" timestamp");
        }
        if (this.b == null) {
            sb.append(" type");
        }
        if (this.c == null) {
            sb.append(" app");
        }
        if (this.d == null) {
            sb.append(" device");
        }
        throw new IllegalStateException(com.google.android.gms.measurement.internal.Z.i("Missing required properties:", sb));
    }
}
