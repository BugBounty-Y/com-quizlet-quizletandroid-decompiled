package com.google.firebase.crashlytics.internal.model;

/* loaded from: classes2.dex */
public final class Y extends A0 {
    public final long a;
    public final String b;
    public final String c;
    public final long d;
    public final int e;

    public Y(int i, long j, long j2, String str, String str2) {
        this.a = j;
        this.b = str;
        this.c = str2;
        this.d = j2;
        this.e = i;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof A0) {
            A0 a0 = (A0) obj;
            if (this.a == ((Y) a0).a) {
                Y y = (Y) a0;
                if (this.b.equals(y.b)) {
                    String str = y.c;
                    String str2 = this.c;
                    if (str2 != null ? str2.equals(str) : str == null) {
                        if (this.d == y.d && this.e == y.e) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        long j = this.a;
        int iHashCode = (((((int) (j ^ (j >>> 32))) ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003;
        String str = this.c;
        int iHashCode2 = (iHashCode ^ (str == null ? 0 : str.hashCode())) * 1000003;
        long j2 = this.d;
        return ((iHashCode2 ^ ((int) ((j2 >>> 32) ^ j2))) * 1000003) ^ this.e;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Frame{pc=");
        sb.append(this.a);
        sb.append(", symbol=");
        sb.append(this.b);
        sb.append(", file=");
        sb.append(this.c);
        sb.append(", offset=");
        sb.append(this.d);
        sb.append(", importance=");
        return android.support.v4.media.session.a.r(sb, this.e, "}");
    }
}
