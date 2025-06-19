package com.google.firebase.installations.remote;

import androidx.appcompat.widget.C0122z;
import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class b {
    public final String a;
    public final long b;
    public final int c;

    public b(int i, long j, String str) {
        this.a = str;
        this.b = j;
        this.c = i;
    }

    public static C0122z a() {
        C0122z c0122z = new C0122z(17, (char) 0);
        c0122z.d = 0L;
        return c0122z;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        String str = this.a;
        if (str == null) {
            if (bVar.a != null) {
                return false;
            }
        } else if (!str.equals(bVar.a)) {
            return false;
        }
        if (this.b != bVar.b) {
            return false;
        }
        int i = bVar.c;
        int i2 = this.c;
        return i2 == 0 ? i == 0 : AbstractC0147y.a(i2, i);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = str == null ? 0 : str.hashCode();
        long j = this.b;
        int i = (((iHashCode ^ 1000003) * 1000003) ^ ((int) (j ^ (j >>> 32)))) * 1000003;
        int i2 = this.c;
        return (i2 != 0 ? AbstractC0147y.k(i2) : 0) ^ i;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TokenResult{token=");
        sb.append(this.a);
        sb.append(", tokenExpirationTimestamp=");
        sb.append(this.b);
        sb.append(", responseCode=");
        int i = this.c;
        sb.append(i != 1 ? i != 2 ? i != 3 ? "null" : "AUTH_ERROR" : "BAD_CONFIG" : "OK");
        sb.append("}");
        return sb.toString();
    }
}
