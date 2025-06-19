package com.google.firebase.installations.local;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.ads.C2007ea;

/* loaded from: classes2.dex */
public final class a {
    public final String a;
    public final int b;
    public final String c;
    public final String d;
    public final long e;
    public final long f;
    public final String g;

    public a(String str, int i, String str2, String str3, long j, long j2, String str4) {
        this.a = str;
        this.b = i;
        this.c = str2;
        this.d = str3;
        this.e = j;
        this.f = j2;
        this.g = str4;
    }

    public final C2007ea a() {
        C2007ea c2007ea = new C2007ea();
        c2007ea.a = this.a;
        c2007ea.b = this.b;
        c2007ea.c = this.c;
        c2007ea.d = this.d;
        c2007ea.e = Long.valueOf(this.e);
        c2007ea.f = Long.valueOf(this.f);
        c2007ea.g = this.g;
        return c2007ea;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        String str = this.a;
        if (str == null) {
            if (aVar.a != null) {
                return false;
            }
        } else if (!str.equals(aVar.a)) {
            return false;
        }
        if (!AbstractC0147y.a(this.b, aVar.b)) {
            return false;
        }
        String str2 = aVar.c;
        String str3 = this.c;
        if (str3 == null) {
            if (str2 != null) {
                return false;
            }
        } else if (!str3.equals(str2)) {
            return false;
        }
        String str4 = aVar.d;
        String str5 = this.d;
        if (str5 == null) {
            if (str4 != null) {
                return false;
            }
        } else if (!str5.equals(str4)) {
            return false;
        }
        if (this.e != aVar.e || this.f != aVar.f) {
            return false;
        }
        String str6 = aVar.g;
        String str7 = this.g;
        return str7 == null ? str6 == null : str7.equals(str6);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = ((((str == null ? 0 : str.hashCode()) ^ 1000003) * 1000003) ^ AbstractC0147y.k(this.b)) * 1000003;
        String str2 = this.c;
        int iHashCode2 = (iHashCode ^ (str2 == null ? 0 : str2.hashCode())) * 1000003;
        String str3 = this.d;
        int iHashCode3 = (iHashCode2 ^ (str3 == null ? 0 : str3.hashCode())) * 1000003;
        long j = this.e;
        int i = (iHashCode3 ^ ((int) (j ^ (j >>> 32)))) * 1000003;
        long j2 = this.f;
        int i2 = (i ^ ((int) (j2 ^ (j2 >>> 32)))) * 1000003;
        String str4 = this.g;
        return (str4 != null ? str4.hashCode() : 0) ^ i2;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PersistedInstallationEntry{firebaseInstallationId=");
        sb.append(this.a);
        sb.append(", registrationStatus=");
        int i = this.b;
        sb.append(i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? "null" : "REGISTER_ERROR" : "REGISTERED" : "UNREGISTERED" : "NOT_GENERATED" : "ATTEMPT_MIGRATION");
        sb.append(", authToken=");
        sb.append(this.c);
        sb.append(", refreshToken=");
        sb.append(this.d);
        sb.append(", expiresInSecs=");
        sb.append(this.e);
        sb.append(", tokenCreationEpochInSecs=");
        sb.append(this.f);
        sb.append(", fisError=");
        return android.support.v4.media.session.a.t(sb, this.g, "}");
    }
}
