package kotlinx.serialization.internal;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class L implements kotlin.reflect.o {
    public final kotlin.reflect.o a;

    public L(kotlin.reflect.o origin) {
        Intrinsics.checkNotNullParameter(origin, "origin");
        this.a = origin;
    }

    @Override // kotlin.reflect.o
    public final List a() {
        return this.a.a();
    }

    @Override // kotlin.reflect.o
    public final boolean b() {
        return this.a.b();
    }

    @Override // kotlin.reflect.o
    public final kotlin.reflect.d d() {
        return this.a.d();
    }

    public final boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        L l = obj instanceof L ? (L) obj : null;
        kotlin.reflect.o oVar = l != null ? l.a : null;
        kotlin.reflect.o oVar2 = this.a;
        if (!Intrinsics.b(oVar2, oVar)) {
            return false;
        }
        kotlin.reflect.d dVarD = oVar2.d();
        if (dVarD instanceof kotlin.reflect.c) {
            kotlin.reflect.o oVar3 = obj instanceof kotlin.reflect.o ? (kotlin.reflect.o) obj : null;
            kotlin.reflect.d dVarD2 = oVar3 != null ? oVar3.d() : null;
            if (dVarD2 != null && (dVarD2 instanceof kotlin.reflect.c)) {
                return kotlin.jvm.a.b((kotlin.reflect.c) dVarD).equals(kotlin.jvm.a.b((kotlin.reflect.c) dVarD2));
            }
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "KTypeWrapper: " + this.a;
    }
}
