package com.braze.models.response;

/* loaded from: classes.dex */
public final class j {
    public final int a;
    public final int b;

    public j(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return this.a == jVar.a && this.b == jVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RateLimitEndpointConfig(capacity=");
        sb.append(this.a);
        sb.append(", refillRate=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }
}
