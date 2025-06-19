package androidx.navigation;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.navigation.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1266b extends B {
    @Override // androidx.navigation.B
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof C1266b) || !super.equals(obj)) {
            return false;
        }
        return true;
    }

    @Override // androidx.navigation.B
    public final int hashCode() {
        return super.hashCode() * 961;
    }

    @Override // androidx.navigation.B
    public final String toString() {
        String str = super.toString();
        Intrinsics.checkNotNullExpressionValue(str, "toString(...)");
        return str;
    }
}
