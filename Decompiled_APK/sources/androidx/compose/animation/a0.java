package androidx.compose.animation;

import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a0 {
    public static final a0 b = new a0(new q0((c0) null, (o0) null, (I) null, (E) null, (LinkedHashMap) null, 63));
    public final q0 a;

    public a0(q0 q0Var) {
        this.a = q0Var;
    }

    public final a0 a(a0 a0Var) {
        E e = null;
        q0 q0Var = a0Var.a;
        q0 q0Var2 = this.a;
        c0 c0Var = q0Var.a;
        if (c0Var == null) {
            c0Var = q0Var2.a;
        }
        o0 o0Var = q0Var.b;
        if (o0Var == null) {
            o0Var = q0Var2.b;
        }
        I i = q0Var.c;
        if (i == null) {
            i = q0Var2.c;
        }
        return new a0(new q0(c0Var, o0Var, i, e, kotlin.collections.V.h(q0Var2.e, q0Var.e), 16));
    }

    public final boolean equals(Object obj) {
        return (obj instanceof a0) && Intrinsics.b(((a0) obj).a, this.a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        if (equals(b)) {
            return "EnterTransition.None";
        }
        StringBuilder sb = new StringBuilder("EnterTransition: \nFade - ");
        q0 q0Var = this.a;
        c0 c0Var = q0Var.a;
        sb.append(c0Var != null ? c0Var.toString() : null);
        sb.append(",\nSlide - ");
        o0 o0Var = q0Var.b;
        sb.append(o0Var != null ? o0Var.toString() : null);
        sb.append(",\nShrink - ");
        I i = q0Var.c;
        sb.append(i != null ? i.toString() : null);
        sb.append(",\nScale - ");
        sb.append((String) null);
        return sb.toString();
    }
}
