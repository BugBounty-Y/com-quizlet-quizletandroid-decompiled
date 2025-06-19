package com.google.android.gms.measurement.internal;

/* renamed from: com.google.android.gms.measurement.internal.n, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3882n {
    public final String a;
    public final String b;
    public final long c;
    public final long d;
    public final long e;
    public final long f;
    public final long g;
    public final Long h;
    public final Long i;
    public final Long j;
    public final Boolean k;

    public C3882n(String str, String str2, long j, long j2, long j3, long j4, long j5, Long l, Long l2, Long l3, Boolean bool) {
        com.google.android.gms.common.internal.u.e(str);
        com.google.android.gms.common.internal.u.e(str2);
        com.google.android.gms.common.internal.u.b(j >= 0);
        com.google.android.gms.common.internal.u.b(j2 >= 0);
        com.google.android.gms.common.internal.u.b(j3 >= 0);
        com.google.android.gms.common.internal.u.b(j5 >= 0);
        this.a = str;
        this.b = str2;
        this.c = j;
        this.d = j2;
        this.e = j3;
        this.f = j4;
        this.g = j5;
        this.h = l;
        this.i = l2;
        this.j = l3;
        this.k = bool;
    }

    public final C3882n a(Long l, Long l2, Boolean bool) {
        return new C3882n(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, l, l2, bool);
    }

    public final C3882n b(long j) {
        return new C3882n(this.a, this.b, this.c, this.d, this.e, j, this.g, this.h, this.i, this.j, this.k);
    }
}
