package com.google.firebase.crashlytics.internal.model;

/* loaded from: classes2.dex */
public final class B extends O0 {
    public final String b;
    public final String c;
    public final int d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;
    public final String j;
    public final J k;
    public final G l;
    public final D m;

    public B(String str, String str2, int i, String str3, String str4, String str5, String str6, String str7, String str8, J j, G g, D d) {
        this.b = str;
        this.c = str2;
        this.d = i;
        this.e = str3;
        this.f = str4;
        this.g = str5;
        this.h = str6;
        this.i = str7;
        this.j = str8;
        this.k = j;
        this.l = g;
        this.m = d;
    }

    public final A a() {
        A a = new A();
        a.a = this.b;
        a.b = this.c;
        a.c = this.d;
        a.d = this.e;
        a.e = this.f;
        a.f = this.g;
        a.g = this.h;
        a.h = this.i;
        a.i = this.j;
        a.j = this.k;
        a.k = this.l;
        a.l = this.m;
        a.m = (byte) 1;
        return a;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof O0)) {
            return false;
        }
        B b = (B) ((O0) obj);
        if (!this.b.equals(b.b)) {
            return false;
        }
        if (!this.c.equals(b.c) || this.d != b.d || !this.e.equals(b.e)) {
            return false;
        }
        String str = b.f;
        String str2 = this.f;
        if (str2 == null) {
            if (str != null) {
                return false;
            }
        } else if (!str2.equals(str)) {
            return false;
        }
        String str3 = b.g;
        String str4 = this.g;
        if (str4 == null) {
            if (str3 != null) {
                return false;
            }
        } else if (!str4.equals(str3)) {
            return false;
        }
        String str5 = b.h;
        String str6 = this.h;
        if (str6 == null) {
            if (str5 != null) {
                return false;
            }
        } else if (!str6.equals(str5)) {
            return false;
        }
        if (!this.i.equals(b.i) || !this.j.equals(b.j)) {
            return false;
        }
        J j = b.k;
        J j2 = this.k;
        if (j2 == null) {
            if (j != null) {
                return false;
            }
        } else if (!j2.equals(j)) {
            return false;
        }
        G g = b.l;
        G g2 = this.l;
        if (g2 == null) {
            if (g != null) {
                return false;
            }
        } else if (!g2.equals(g)) {
            return false;
        }
        D d = b.m;
        D d2 = this.m;
        return d2 == null ? d == null : d2.equals(d);
    }

    public final int hashCode() {
        int iHashCode = (((((((this.b.hashCode() ^ 1000003) * 1000003) ^ this.c.hashCode()) * 1000003) ^ this.d) * 1000003) ^ this.e.hashCode()) * 1000003;
        String str = this.f;
        int iHashCode2 = (iHashCode ^ (str == null ? 0 : str.hashCode())) * 1000003;
        String str2 = this.g;
        int iHashCode3 = (iHashCode2 ^ (str2 == null ? 0 : str2.hashCode())) * 1000003;
        String str3 = this.h;
        int iHashCode4 = (((((iHashCode3 ^ (str3 == null ? 0 : str3.hashCode())) * 1000003) ^ this.i.hashCode()) * 1000003) ^ this.j.hashCode()) * 1000003;
        J j = this.k;
        int iHashCode5 = (iHashCode4 ^ (j == null ? 0 : j.hashCode())) * 1000003;
        G g = this.l;
        int iHashCode6 = (iHashCode5 ^ (g == null ? 0 : g.hashCode())) * 1000003;
        D d = this.m;
        return iHashCode6 ^ (d != null ? d.hashCode() : 0);
    }

    public final String toString() {
        return "CrashlyticsReport{sdkVersion=" + this.b + ", gmpAppId=" + this.c + ", platform=" + this.d + ", installationUuid=" + this.e + ", firebaseInstallationId=" + this.f + ", firebaseAuthenticationToken=" + this.g + ", appQualitySessionId=" + this.h + ", buildVersion=" + this.i + ", displayVersion=" + this.j + ", session=" + this.k + ", ndkPayload=" + this.l + ", appExitInfo=" + this.m + "}";
    }
}
