package androidx.glance;

import androidx.compose.animation.d0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h implements p {
    public final p a;
    public final p b;

    public h(p pVar, p pVar2) {
        this.a = pVar;
        this.b = pVar2;
    }

    @Override // androidx.glance.p
    public final Object a(Object obj, Function2 function2) {
        return this.b.a(this.a.a(obj, function2), function2);
    }

    @Override // androidx.glance.p
    public final boolean b() {
        return this.a.b() && this.b.b();
    }

    @Override // androidx.glance.p
    public final boolean c(Function1 function1) {
        return this.a.c(function1) || this.b.c(function1);
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && Intrinsics.b(this.b, hVar.b);
    }

    public final int hashCode() {
        return (this.b.hashCode() * 31) + this.a.hashCode();
    }

    public final String toString() {
        return d0.r(new StringBuilder("["), (String) a("", g.b), ']');
    }
}
