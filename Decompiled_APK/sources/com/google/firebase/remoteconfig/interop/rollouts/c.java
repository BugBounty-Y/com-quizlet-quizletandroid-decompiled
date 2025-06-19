package com.google.firebase.remoteconfig.interop.rollouts;

/* loaded from: classes2.dex */
public final class c extends e {
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final long f;

    public c(String str, String str2, String str3, String str4, long j) {
        this.b = str;
        this.c = str2;
        this.d = str3;
        this.e = str4;
        this.f = j;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof e) {
            e eVar = (e) obj;
            if (this.b.equals(((c) eVar).b)) {
                c cVar = (c) eVar;
                if (this.c.equals(cVar.c) && this.d.equals(cVar.d) && this.e.equals(cVar.e) && this.f == cVar.f) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = (((((((this.b.hashCode() ^ 1000003) * 1000003) ^ this.c.hashCode()) * 1000003) ^ this.d.hashCode()) * 1000003) ^ this.e.hashCode()) * 1000003;
        long j = this.f;
        return iHashCode ^ ((int) ((j >>> 32) ^ j));
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RolloutAssignment{rolloutId=");
        sb.append(this.b);
        sb.append(", variantId=");
        sb.append(this.c);
        sb.append(", parameterKey=");
        sb.append(this.d);
        sb.append(", parameterValue=");
        sb.append(this.e);
        sb.append(", templateVersion=");
        return android.support.v4.media.session.a.g(this.f, "}", sb);
    }
}
