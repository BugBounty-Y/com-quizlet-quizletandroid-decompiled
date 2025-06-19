package com.google.firebase.installations.remote;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class a {
    public final String a;
    public final String b;
    public final String c;
    public final b d;
    public final int e;

    public a(String str, String str2, String str3, b bVar, int i) {
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = bVar;
        this.e = i;
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
        String str2 = this.b;
        if (str2 == null) {
            if (aVar.b != null) {
                return false;
            }
        } else if (!str2.equals(aVar.b)) {
            return false;
        }
        String str3 = this.c;
        if (str3 == null) {
            if (aVar.c != null) {
                return false;
            }
        } else if (!str3.equals(aVar.c)) {
            return false;
        }
        b bVar = this.d;
        if (bVar == null) {
            if (aVar.d != null) {
                return false;
            }
        } else if (!bVar.equals(aVar.d)) {
            return false;
        }
        int i = this.e;
        return i == 0 ? aVar.e == 0 : AbstractC0147y.a(i, aVar.e);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = ((str == null ? 0 : str.hashCode()) ^ 1000003) * 1000003;
        String str2 = this.b;
        int iHashCode2 = (iHashCode ^ (str2 == null ? 0 : str2.hashCode())) * 1000003;
        String str3 = this.c;
        int iHashCode3 = (iHashCode2 ^ (str3 == null ? 0 : str3.hashCode())) * 1000003;
        b bVar = this.d;
        int iHashCode4 = (iHashCode3 ^ (bVar == null ? 0 : bVar.hashCode())) * 1000003;
        int i = this.e;
        return (i != 0 ? AbstractC0147y.k(i) : 0) ^ iHashCode4;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("InstallationResponse{uri=");
        sb.append(this.a);
        sb.append(", fid=");
        sb.append(this.b);
        sb.append(", refreshToken=");
        sb.append(this.c);
        sb.append(", authToken=");
        sb.append(this.d);
        sb.append(", responseCode=");
        int i = this.e;
        sb.append(i != 1 ? i != 2 ? "null" : "BAD_CONFIG" : "OK");
        sb.append("}");
        return sb.toString();
    }
}
