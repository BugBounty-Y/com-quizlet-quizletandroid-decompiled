package com.quizlet.data.model;

/* loaded from: classes2.dex */
public final class X {
    public final int a;
    public final int b;
    public final boolean c;
    public final int d;

    public X(int i, int i2) {
        this.a = i;
        this.b = i2;
        this.c = i > i2 || (i2 == 0 && i == 0);
        this.d = Math.max(i2 - i, 0);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof X)) {
            return false;
        }
        X x = (X) obj;
        return this.a == x.a && this.b == x.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExplanationsMeteringInfo(numEvents=");
        sb.append(this.a);
        sb.append(", threshold=");
        return android.support.v4.media.session.a.r(sb, this.b, ")");
    }
}
