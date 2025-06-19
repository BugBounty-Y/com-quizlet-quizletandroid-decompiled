package androidx.compose.runtime;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class I implements Z0 {
    public final InterfaceC0773a0 a;

    public I(InterfaceC0773a0 interfaceC0773a0) {
        this.a = interfaceC0773a0;
    }

    @Override // androidx.compose.runtime.Z0
    public final Object a(InterfaceC0803j0 interfaceC0803j0) {
        return ((L0) this.a).getValue();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof I) && Intrinsics.b(this.a, ((I) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "DynamicValueHolder(state=" + this.a + ')';
    }
}
