package androidx.compose.runtime;

import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class C implements Z0 {
    public final kotlin.jvm.internal.r a;

    /* JADX WARN: Multi-variable type inference failed */
    public C(Function1 function1) {
        this.a = (kotlin.jvm.internal.r) function1;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // androidx.compose.runtime.Z0
    public final Object a(InterfaceC0803j0 interfaceC0803j0) {
        return this.a.invoke(interfaceC0803j0);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C) && this.a.equals(((C) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ComputedValueHolder(compute=" + this.a + ')';
    }
}
