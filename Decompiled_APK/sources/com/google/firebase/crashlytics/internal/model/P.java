package com.google.firebase.crashlytics.internal.model;

/* loaded from: classes2.dex */
public final class P extends K0 {
    public final long a;
    public final String b;
    public final Q c;
    public final C3929c0 d;
    public final C3931d0 e;
    public final C3939h0 f;

    public P(long j, String str, Q q, C3929c0 c3929c0, C3931d0 c3931d0, C3939h0 c3939h0) {
        this.a = j;
        this.b = str;
        this.c = q;
        this.d = c3929c0;
        this.e = c3931d0;
        this.f = c3939h0;
    }

    public final O a() {
        O o = new O();
        o.a = this.a;
        o.b = this.b;
        o.c = this.c;
        o.d = this.d;
        o.e = this.e;
        o.f = this.f;
        o.g = (byte) 1;
        return o;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof K0)) {
            return false;
        }
        P p = (P) ((K0) obj);
        if (this.a != p.a) {
            return false;
        }
        if (!this.b.equals(p.b) || !this.c.equals(p.c) || !this.d.equals(p.d)) {
            return false;
        }
        C3931d0 c3931d0 = p.e;
        C3931d0 c3931d02 = this.e;
        if (c3931d02 == null) {
            if (c3931d0 != null) {
                return false;
            }
        } else if (!c3931d02.equals(c3931d0)) {
            return false;
        }
        C3939h0 c3939h0 = p.f;
        C3939h0 c3939h02 = this.f;
        return c3939h02 == null ? c3939h0 == null : c3939h02.equals(c3939h0);
    }

    public final int hashCode() {
        long j = this.a;
        int iHashCode = (((((((((int) (j ^ (j >>> 32))) ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003) ^ this.c.hashCode()) * 1000003) ^ this.d.hashCode()) * 1000003;
        C3931d0 c3931d0 = this.e;
        int iHashCode2 = (iHashCode ^ (c3931d0 == null ? 0 : c3931d0.hashCode())) * 1000003;
        C3939h0 c3939h0 = this.f;
        return iHashCode2 ^ (c3939h0 != null ? c3939h0.hashCode() : 0);
    }

    public final String toString() {
        return "Event{timestamp=" + this.a + ", type=" + this.b + ", app=" + this.c + ", device=" + this.d + ", log=" + this.e + ", rollouts=" + this.f + "}";
    }
}
