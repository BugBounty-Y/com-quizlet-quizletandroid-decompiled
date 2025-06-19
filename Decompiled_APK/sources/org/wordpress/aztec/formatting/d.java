package org.wordpress.aztec.formatting;

/* loaded from: classes3.dex */
public final class d {
    public final boolean a;
    public final int b;

    public d(boolean z, int i) {
        this.a = z;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && this.b == dVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ListItemStyle(strikeThroughCheckedItems=");
        sb.append(this.a);
        sb.append(", checkedItemsTextColor=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }
}
