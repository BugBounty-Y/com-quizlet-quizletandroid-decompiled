package androidx.compose.runtime;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class Y0 implements Z0 {
    public final Object a;

    public Y0(Object obj) {
        this.a = obj;
    }

    @Override // androidx.compose.runtime.Z0
    public final Object a(InterfaceC0803j0 interfaceC0803j0) {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof Y0) && Intrinsics.b(this.a, ((Y0) obj).a);
    }

    public final int hashCode() {
        Object obj = this.a;
        if (obj == null) {
            return 0;
        }
        return obj.hashCode();
    }

    public final String toString() {
        return "StaticValueHolder(value=" + this.a + ')';
    }
}
