package com.google.firebase.crashlytics.internal.model;

import java.util.List;

/* loaded from: classes2.dex */
public final class I {
    public String a;
    public String b;
    public String c;
    public long d;
    public Long e;
    public boolean f;
    public K g;
    public C3945k0 h;
    public C3943j0 i;
    public N j;
    public List k;
    public int l;
    public byte m;

    public final J a() {
        String str;
        String str2;
        K k;
        if (this.m == 7 && (str = this.a) != null && (str2 = this.b) != null && (k = this.g) != null) {
            return new J(str, str2, this.c, this.d, this.e, this.f, k, this.h, this.i, this.j, this.k, this.l);
        }
        StringBuilder sb = new StringBuilder();
        if (this.a == null) {
            sb.append(" generator");
        }
        if (this.b == null) {
            sb.append(" identifier");
        }
        if ((this.m & 1) == 0) {
            sb.append(" startedAt");
        }
        if ((this.m & 2) == 0) {
            sb.append(" crashed");
        }
        if (this.g == null) {
            sb.append(" app");
        }
        if ((this.m & 4) == 0) {
            sb.append(" generatorType");
        }
        throw new IllegalStateException(com.google.android.gms.measurement.internal.Z.i("Missing required properties:", sb));
    }
}
