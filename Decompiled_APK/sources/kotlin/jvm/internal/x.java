package kotlin.jvm.internal;

/* loaded from: classes3.dex */
public final class x implements InterfaceC4948g {
    public final Class a;

    public x(Class jClass) {
        Intrinsics.checkNotNullParameter(jClass, "jClass");
        Intrinsics.checkNotNullParameter("", "moduleName");
        this.a = jClass;
    }

    @Override // kotlin.jvm.internal.InterfaceC4948g
    public final Class c() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof x) {
            return Intrinsics.b(this.a, ((x) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return this.a.toString() + " (Kotlin reflection is not available)";
    }
}
