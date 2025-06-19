package androidx.compose.animation;

import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b0 {
    public static final b0 b;
    public static final b0 c;
    public final q0 a;

    static {
        E e = null;
        LinkedHashMap linkedHashMap = null;
        c0 c0Var = null;
        o0 o0Var = null;
        I i = null;
        b = new b0(new q0(c0Var, o0Var, i, e, linkedHashMap, 63));
        c = new b0(new q0(c0Var, o0Var, i, e, linkedHashMap, 47));
    }

    public b0(q0 q0Var) {
        this.a = q0Var;
    }

    public final b0 a(b0 b0Var) {
        q0 q0Var = b0Var.a;
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
        return new b0(new q0(c0Var, o0Var, i, (E) null, q0Var.d || q0Var2.d, kotlin.collections.V.h(q0Var2.e, q0Var.e)));
    }

    public final boolean equals(Object obj) {
        return (obj instanceof b0) && Intrinsics.b(((b0) obj).a, this.a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        if (equals(b)) {
            return "ExitTransition.None";
        }
        if (equals(c)) {
            return "ExitTransition.KeepUntilTransitionsFinished";
        }
        StringBuilder sb = new StringBuilder("ExitTransition: \nFade - ");
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
        sb.append(",\nKeepUntilTransitionsFinished - ");
        sb.append(q0Var.d);
        return sb.toString();
    }
}
