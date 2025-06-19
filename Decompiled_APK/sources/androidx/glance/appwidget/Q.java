package androidx.glance.appwidget;

import java.util.Map;

/* loaded from: classes.dex */
public final class Q {
    public final Map a;
    public final Object b;

    public Q(Map map, Map map2) {
        this.a = map;
        this.b = map2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Q)) {
            return false;
        }
        Q q = (Q) obj;
        return this.a.equals(q.a) && this.b.equals(q.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "State(receiverToProviderName=" + this.a + ", providerNameToReceivers=" + this.b + ')';
    }
}
