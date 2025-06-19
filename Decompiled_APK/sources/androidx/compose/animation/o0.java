package androidx.compose.animation;

import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class o0 {
    public final kotlin.jvm.internal.r a;
    public final androidx.compose.animation.core.D b;

    /* JADX WARN: Multi-variable type inference failed */
    public o0(androidx.compose.animation.core.D d, Function1 function1) {
        this.a = (kotlin.jvm.internal.r) function1;
        this.b = d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o0)) {
            return false;
        }
        o0 o0Var = (o0) obj;
        return this.a.equals(o0Var.a) && this.b.equals(o0Var.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Slide(slideOffset=" + this.a + ", animationSpec=" + this.b + ')';
    }
}
