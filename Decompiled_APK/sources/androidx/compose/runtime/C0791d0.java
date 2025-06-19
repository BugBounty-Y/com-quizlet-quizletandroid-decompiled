package androidx.compose.runtime;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.runtime.d0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0791d0 {
    public final String a;

    public C0791d0(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C0791d0) && Intrinsics.b(this.a, ((C0791d0) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return androidx.compose.animation.d0.r(new StringBuilder("OpaqueKey(key="), this.a, ')');
    }
}
