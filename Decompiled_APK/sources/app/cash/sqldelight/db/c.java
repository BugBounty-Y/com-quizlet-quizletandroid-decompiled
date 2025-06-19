package app.cash.sqldelight.db;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c implements d {
    public final Object b;

    public final boolean equals(Object obj) {
        if (obj instanceof c) {
            return Intrinsics.b(this.b, ((c) obj).b);
        }
        return false;
    }

    public final int hashCode() {
        Object obj = this.b;
        if (obj == null) {
            return 0;
        }
        return obj.hashCode();
    }

    public final String toString() {
        return "Value(value=" + this.b + ')';
    }
}
