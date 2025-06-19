package com.google.android.datatransport.cct.internal;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class t extends F {
    public final long a;
    public final Integer b;
    public final o c;
    public final long d;
    public final byte[] e;
    public final String f;
    public final long g;
    public final w h;
    public final p i;

    public t(long j, Integer num, o oVar, long j2, byte[] bArr, String str, long j3, w wVar, p pVar) {
        this.a = j;
        this.b = num;
        this.c = oVar;
        this.d = j2;
        this.e = bArr;
        this.f = str;
        this.g = j3;
        this.h = wVar;
        this.i = pVar;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof F)) {
            return false;
        }
        F f = (F) obj;
        t tVar = (t) f;
        if (this.a != tVar.a) {
            return false;
        }
        Integer num = this.b;
        if (num == null) {
            if (tVar.b != null) {
                return false;
            }
        } else if (!num.equals(tVar.b)) {
            return false;
        }
        o oVar = this.c;
        if (oVar == null) {
            if (tVar.c != null) {
                return false;
            }
        } else if (!oVar.equals(tVar.c)) {
            return false;
        }
        if (this.d != tVar.d) {
            return false;
        }
        if (!Arrays.equals(this.e, f instanceof t ? ((t) f).e : tVar.e)) {
            return false;
        }
        String str = tVar.f;
        String str2 = this.f;
        if (str2 == null) {
            if (str != null) {
                return false;
            }
        } else if (!str2.equals(str)) {
            return false;
        }
        if (this.g != tVar.g) {
            return false;
        }
        w wVar = tVar.h;
        w wVar2 = this.h;
        if (wVar2 == null) {
            if (wVar != null) {
                return false;
            }
        } else if (!wVar2.equals(wVar)) {
            return false;
        }
        p pVar = tVar.i;
        p pVar2 = this.i;
        return pVar2 == null ? pVar == null : pVar2.equals(pVar);
    }

    public final int hashCode() {
        long j = this.a;
        int i = (((int) (j ^ (j >>> 32))) ^ 1000003) * 1000003;
        Integer num = this.b;
        int iHashCode = (i ^ (num == null ? 0 : num.hashCode())) * 1000003;
        o oVar = this.c;
        int iHashCode2 = (iHashCode ^ (oVar == null ? 0 : oVar.hashCode())) * 1000003;
        long j2 = this.d;
        int iHashCode3 = (((iHashCode2 ^ ((int) (j2 ^ (j2 >>> 32)))) * 1000003) ^ Arrays.hashCode(this.e)) * 1000003;
        String str = this.f;
        int iHashCode4 = (iHashCode3 ^ (str == null ? 0 : str.hashCode())) * 1000003;
        long j3 = this.g;
        int i2 = (iHashCode4 ^ ((int) (j3 ^ (j3 >>> 32)))) * 1000003;
        w wVar = this.h;
        int iHashCode5 = (i2 ^ (wVar == null ? 0 : wVar.hashCode())) * 1000003;
        p pVar = this.i;
        return iHashCode5 ^ (pVar != null ? pVar.hashCode() : 0);
    }

    public final String toString() {
        return "LogEvent{eventTimeMs=" + this.a + ", eventCode=" + this.b + ", complianceData=" + this.c + ", eventUptimeMs=" + this.d + ", sourceExtension=" + Arrays.toString(this.e) + ", sourceExtensionJsonProto3=" + this.f + ", timezoneOffsetSeconds=" + this.g + ", networkConnectionInfo=" + this.h + ", experimentIds=" + this.i + "}";
    }
}
