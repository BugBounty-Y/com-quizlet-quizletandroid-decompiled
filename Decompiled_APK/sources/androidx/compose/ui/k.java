package androidx.compose.ui;

import androidx.compose.animation.d0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k implements q {
    public final q b;
    public final q c;

    public k(q qVar, q qVar2) {
        this.b = qVar;
        this.c = qVar2;
    }

    @Override // androidx.compose.ui.q
    public final Object a(Object obj, Function2 function2) {
        return this.c.a(this.b.a(obj, function2), function2);
    }

    @Override // androidx.compose.ui.q
    public final boolean d(Function1 function1) {
        return this.b.d(function1) && this.c.d(function1);
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return Intrinsics.b(this.b, kVar.b) && Intrinsics.b(this.c, kVar.c);
    }

    public final int hashCode() {
        return (this.c.hashCode() * 31) + this.b.hashCode();
    }

    public final String toString() {
        return d0.r(new StringBuilder("["), (String) a("", j.a), ']');
    }
}
