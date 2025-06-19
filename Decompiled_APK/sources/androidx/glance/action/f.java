package androidx.glance.action;

import java.util.LinkedHashMap;

/* loaded from: classes.dex */
public final class f {
    public final LinkedHashMap a;

    public f(LinkedHashMap linkedHashMap) {
        this.a = linkedHashMap;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof f) {
            return this.a.equals(((f) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return this.a.toString();
    }
}
