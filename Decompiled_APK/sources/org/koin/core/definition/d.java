package org.koin.core.definition;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final org.koin.core.module.a a;
    public final org.koin.core.instance.b b;

    public d(org.koin.core.module.a module, org.koin.core.instance.b factory) {
        Intrinsics.checkNotNullParameter(module, "module");
        Intrinsics.checkNotNullParameter(factory, "factory");
        this.a = module;
        this.b = factory;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && Intrinsics.b(this.b, dVar.b);
    }

    public final int hashCode() {
        return this.b.a.hashCode() + (this.a.a.hashCode() * 31);
    }

    public final String toString() {
        return "KoinDefinition(module=" + this.a + ", factory=" + this.b + ')';
    }
}
