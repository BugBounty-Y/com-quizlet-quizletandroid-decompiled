package com.google.firebase.crashlytics.internal.model;

import java.util.List;

/* loaded from: classes2.dex */
public final class J extends N0 {
    public final String a;
    public final String b;
    public final String c;
    public final long d;
    public final Long e;
    public final boolean f;
    public final K g;
    public final C3945k0 h;
    public final C3943j0 i;
    public final N j;
    public final List k;
    public final int l;

    public J(String str, String str2, String str3, long j, Long l, boolean z, K k, C3945k0 c3945k0, C3943j0 c3943j0, N n, List list, int i) {
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = j;
        this.e = l;
        this.f = z;
        this.g = k;
        this.h = c3945k0;
        this.i = c3943j0;
        this.j = n;
        this.k = list;
        this.l = i;
    }

    public final I a() {
        I i = new I();
        i.a = this.a;
        i.b = this.b;
        i.c = this.c;
        i.d = this.d;
        i.e = this.e;
        i.f = this.f;
        i.g = this.g;
        i.h = this.h;
        i.i = this.i;
        i.j = this.j;
        i.k = this.k;
        i.l = this.l;
        i.m = (byte) 7;
        return i;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof N0)) {
            return false;
        }
        J j = (J) ((N0) obj);
        if (!this.a.equals(j.a)) {
            return false;
        }
        if (!this.b.equals(j.b)) {
            return false;
        }
        String str = j.c;
        String str2 = this.c;
        if (str2 == null) {
            if (str != null) {
                return false;
            }
        } else if (!str2.equals(str)) {
            return false;
        }
        if (this.d != j.d) {
            return false;
        }
        Long l = j.e;
        Long l2 = this.e;
        if (l2 == null) {
            if (l != null) {
                return false;
            }
        } else if (!l2.equals(l)) {
            return false;
        }
        if (this.f != j.f || !this.g.equals(j.g)) {
            return false;
        }
        C3945k0 c3945k0 = j.h;
        C3945k0 c3945k02 = this.h;
        if (c3945k02 == null) {
            if (c3945k0 != null) {
                return false;
            }
        } else if (!c3945k02.equals(c3945k0)) {
            return false;
        }
        C3943j0 c3943j0 = j.i;
        C3943j0 c3943j02 = this.i;
        if (c3943j02 == null) {
            if (c3943j0 != null) {
                return false;
            }
        } else if (!c3943j02.equals(c3943j0)) {
            return false;
        }
        N n = j.j;
        N n2 = this.j;
        if (n2 == null) {
            if (n != null) {
                return false;
            }
        } else if (!n2.equals(n)) {
            return false;
        }
        List list = j.k;
        List list2 = this.k;
        if (list2 == null) {
            if (list != null) {
                return false;
            }
        } else if (!list2.equals(list)) {
            return false;
        }
        return this.l == j.l;
    }

    public final int hashCode() {
        int iHashCode = (((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003;
        String str = this.c;
        int iHashCode2 = (iHashCode ^ (str == null ? 0 : str.hashCode())) * 1000003;
        long j = this.d;
        int i = (iHashCode2 ^ ((int) (j ^ (j >>> 32)))) * 1000003;
        Long l = this.e;
        int iHashCode3 = (((((i ^ (l == null ? 0 : l.hashCode())) * 1000003) ^ (this.f ? 1231 : 1237)) * 1000003) ^ this.g.hashCode()) * 1000003;
        C3945k0 c3945k0 = this.h;
        int iHashCode4 = (iHashCode3 ^ (c3945k0 == null ? 0 : c3945k0.hashCode())) * 1000003;
        C3943j0 c3943j0 = this.i;
        int iHashCode5 = (iHashCode4 ^ (c3943j0 == null ? 0 : c3943j0.hashCode())) * 1000003;
        N n = this.j;
        int iHashCode6 = (iHashCode5 ^ (n == null ? 0 : n.hashCode())) * 1000003;
        List list = this.k;
        return ((iHashCode6 ^ (list != null ? list.hashCode() : 0)) * 1000003) ^ this.l;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Session{generator=");
        sb.append(this.a);
        sb.append(", identifier=");
        sb.append(this.b);
        sb.append(", appQualitySessionId=");
        sb.append(this.c);
        sb.append(", startedAt=");
        sb.append(this.d);
        sb.append(", endedAt=");
        sb.append(this.e);
        sb.append(", crashed=");
        sb.append(this.f);
        sb.append(", app=");
        sb.append(this.g);
        sb.append(", user=");
        sb.append(this.h);
        sb.append(", os=");
        sb.append(this.i);
        sb.append(", device=");
        sb.append(this.j);
        sb.append(", events=");
        sb.append(this.k);
        sb.append(", generatorType=");
        return android.support.v4.media.session.a.r(sb, this.l, "}");
    }
}
