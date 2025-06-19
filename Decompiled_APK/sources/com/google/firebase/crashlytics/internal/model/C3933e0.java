package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.e0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3933e0 {
    public C3937g0 a;
    public String b;
    public String c;
    public long d;
    public byte e;

    public final C3935f0 a() {
        C3937g0 c3937g0;
        String str;
        String str2;
        if (this.e == 1 && (c3937g0 = this.a) != null && (str = this.b) != null && (str2 = this.c) != null) {
            return new C3935f0(c3937g0, str, str2, this.d);
        }
        StringBuilder sb = new StringBuilder();
        if (this.a == null) {
            sb.append(" rolloutVariant");
        }
        if (this.b == null) {
            sb.append(" parameterKey");
        }
        if (this.c == null) {
            sb.append(" parameterValue");
        }
        if ((1 & this.e) == 0) {
            sb.append(" templateVersion");
        }
        throw new IllegalStateException(com.google.android.gms.measurement.internal.Z.i("Missing required properties:", sb));
    }
}
