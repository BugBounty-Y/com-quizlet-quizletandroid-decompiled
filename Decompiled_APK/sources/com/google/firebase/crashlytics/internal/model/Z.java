package com.google.firebase.crashlytics.internal.model;

/* loaded from: classes2.dex */
public final class Z {
    public String a;
    public int b;
    public int c;
    public boolean d;
    public byte e;

    public final C3925a0 a() {
        String str;
        if (this.e == 7 && (str = this.a) != null) {
            return new C3925a0(this.b, this.c, str, this.d);
        }
        StringBuilder sb = new StringBuilder();
        if (this.a == null) {
            sb.append(" processName");
        }
        if ((this.e & 1) == 0) {
            sb.append(" pid");
        }
        if ((this.e & 2) == 0) {
            sb.append(" importance");
        }
        if ((this.e & 4) == 0) {
            sb.append(" defaultProcess");
        }
        throw new IllegalStateException(com.google.android.gms.measurement.internal.Z.i("Missing required properties:", sb));
    }
}
