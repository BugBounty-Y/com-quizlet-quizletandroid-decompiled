package androidx.glance.action;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public final String a;

    public c(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof c) {
            return Intrinsics.b(this.a, ((c) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return this.a;
    }
}
