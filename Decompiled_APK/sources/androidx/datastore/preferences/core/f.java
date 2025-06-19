package androidx.datastore.preferences.core;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f {
    public final String a;

    public f(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = name;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof f)) {
            return false;
        }
        return Intrinsics.b(this.a, ((f) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return this.a;
    }
}
