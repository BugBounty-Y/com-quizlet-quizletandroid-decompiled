package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.f0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3935f0 extends I0 {
    public final C3937g0 a;
    public final String b;
    public final String c;
    public final long d;

    public C3935f0(C3937g0 c3937g0, String str, String str2, long j) {
        this.a = c3937g0;
        this.b = str;
        this.c = str2;
        this.d = j;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof I0)) {
            return false;
        }
        C3935f0 c3935f0 = (C3935f0) ((I0) obj);
        if (this.a.equals(c3935f0.a)) {
            return this.b.equals(c3935f0.b) && this.c.equals(c3935f0.c) && this.d == c3935f0.d;
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = (((((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003) ^ this.c.hashCode()) * 1000003;
        long j = this.d;
        return iHashCode ^ ((int) (j ^ (j >>> 32)));
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RolloutAssignment{rolloutVariant=");
        sb.append(this.a);
        sb.append(", parameterKey=");
        sb.append(this.b);
        sb.append(", parameterValue=");
        sb.append(this.c);
        sb.append(", templateVersion=");
        return android.support.v4.media.session.a.g(this.d, "}", sb);
    }
}
