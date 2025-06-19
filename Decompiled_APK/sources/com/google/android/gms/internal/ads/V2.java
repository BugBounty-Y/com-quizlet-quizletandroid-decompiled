package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class V2 {
    public final InterfaceC2380n0 a;
    public long b;
    public boolean c;
    public int d;
    public long e;
    public boolean f;
    public boolean g;
    public boolean h;
    public boolean i;
    public boolean j;
    public long k;
    public long l;
    public boolean m;

    public V2(InterfaceC2380n0 interfaceC2380n0) {
        this.a = interfaceC2380n0;
    }

    public final void a(int i) {
        long j = this.l;
        if (j != -9223372036854775807L) {
            long j2 = this.b;
            long j3 = this.k;
            if (j2 == j3) {
                return;
            }
            int i2 = (int) (j2 - j3);
            this.a.f(j, this.m ? 1 : 0, i2, i, null);
        }
    }
}
