package com.google.firebase.crashlytics.internal.model;

/* loaded from: classes2.dex */
public final class X {
    public long a;
    public String b;
    public String c;
    public long d;
    public int e;
    public byte f;

    public final Y a() {
        String str;
        if (this.f == 7 && (str = this.b) != null) {
            return new Y(this.e, this.a, this.d, str, this.c);
        }
        StringBuilder sb = new StringBuilder();
        if ((this.f & 1) == 0) {
            sb.append(" pc");
        }
        if (this.b == null) {
            sb.append(" symbol");
        }
        if ((this.f & 2) == 0) {
            sb.append(" offset");
        }
        if ((this.f & 4) == 0) {
            sb.append(" importance");
        }
        throw new IllegalStateException(com.google.android.gms.measurement.internal.Z.i("Missing required properties:", sb));
    }
}
