package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.b0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3927b0 {
    public Double a;
    public int b;
    public boolean c;
    public int d;
    public long e;
    public long f;
    public byte g;

    public final C3929c0 a() {
        if (this.g == 31) {
            return new C3929c0(this.a, this.b, this.c, this.d, this.e, this.f);
        }
        StringBuilder sb = new StringBuilder();
        if ((this.g & 1) == 0) {
            sb.append(" batteryVelocity");
        }
        if ((this.g & 2) == 0) {
            sb.append(" proximityOn");
        }
        if ((this.g & 4) == 0) {
            sb.append(" orientation");
        }
        if ((this.g & 8) == 0) {
            sb.append(" ramUsed");
        }
        if ((this.g & 16) == 0) {
            sb.append(" diskUsed");
        }
        throw new IllegalStateException(com.google.android.gms.measurement.internal.Z.i("Missing required properties:", sb));
    }
}
