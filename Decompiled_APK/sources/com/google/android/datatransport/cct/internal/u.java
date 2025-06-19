package com.google.android.datatransport.cct.internal;

import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class u extends G {
    public final long a;
    public final long b;
    public final n c;
    public final Integer d;
    public final String e;
    public final ArrayList f;

    public u(long j, long j2, n nVar, Integer num, String str, ArrayList arrayList) {
        K k = K.a;
        this.a = j;
        this.b = j2;
        this.c = nVar;
        this.d = num;
        this.e = str;
        this.f = arrayList;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof G)) {
            return false;
        }
        u uVar = (u) ((G) obj);
        if (this.a != uVar.a) {
            return false;
        }
        if (this.b != uVar.b) {
            return false;
        }
        if (!this.c.equals(uVar.c)) {
            return false;
        }
        Integer num = uVar.d;
        Integer num2 = this.d;
        if (num2 == null) {
            if (num != null) {
                return false;
            }
        } else if (!num2.equals(num)) {
            return false;
        }
        String str = uVar.e;
        String str2 = this.e;
        if (str2 == null) {
            if (str != null) {
                return false;
            }
        } else if (!str2.equals(str)) {
            return false;
        }
        if (!this.f.equals(uVar.f)) {
            return false;
        }
        Object obj2 = K.a;
        return obj2.equals(obj2);
    }

    public final int hashCode() {
        long j = this.a;
        long j2 = this.b;
        int iHashCode = (((((((int) (j ^ (j >>> 32))) ^ 1000003) * 1000003) ^ ((int) ((j2 >>> 32) ^ j2))) * 1000003) ^ this.c.hashCode()) * 1000003;
        Integer num = this.d;
        int iHashCode2 = (iHashCode ^ (num == null ? 0 : num.hashCode())) * 1000003;
        String str = this.e;
        return ((((iHashCode2 ^ (str != null ? str.hashCode() : 0)) * 1000003) ^ this.f.hashCode()) * 1000003) ^ K.a.hashCode();
    }

    public final String toString() {
        return "LogRequest{requestTimeMs=" + this.a + ", requestUptimeMs=" + this.b + ", clientInfo=" + this.c + ", logSource=" + this.d + ", logSourceName=" + this.e + ", logEvents=" + this.f + ", qosTier=" + K.a + "}";
    }
}
