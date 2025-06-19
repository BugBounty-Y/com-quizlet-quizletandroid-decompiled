package com.quizlet.upgrade.upsell.data;

/* loaded from: classes3.dex */
public final class b {
    public final int a;
    public final int b;

    public b(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && this.b == bVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UpsellValueProp(iconRes=");
        sb.append(this.a);
        sb.append(", valuePropRes=");
        return android.support.v4.media.session.a.r(sb, this.b, ")");
    }
}
