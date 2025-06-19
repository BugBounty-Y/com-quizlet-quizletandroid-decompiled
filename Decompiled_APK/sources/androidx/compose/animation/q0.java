package androidx.compose.animation;

import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class q0 {
    public final c0 a;
    public final o0 b;
    public final I c;
    public final boolean d;
    public final Map e;

    public q0(c0 c0Var, o0 o0Var, I i, E e, boolean z, Map map) {
        this.a = c0Var;
        this.b = o0Var;
        this.c = i;
        this.d = z;
        this.e = map;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q0)) {
            return false;
        }
        q0 q0Var = (q0) obj;
        return Intrinsics.b(this.a, q0Var.a) && Intrinsics.b(this.b, q0Var.b) && Intrinsics.b(this.c, q0Var.c) && Intrinsics.b(null, null) && this.d == q0Var.d && Intrinsics.b(this.e, q0Var.e);
    }

    public final int hashCode() {
        c0 c0Var = this.a;
        int iHashCode = (c0Var == null ? 0 : c0Var.hashCode()) * 31;
        o0 o0Var = this.b;
        int iHashCode2 = (iHashCode + (o0Var == null ? 0 : o0Var.hashCode())) * 31;
        I i = this.c;
        return this.e.hashCode() + d0.g((((iHashCode2 + (i == null ? 0 : i.hashCode())) * 31) + 0) * 31, 31, this.d);
    }

    public final String toString() {
        return "TransitionData(fade=" + this.a + ", slide=" + this.b + ", changeSize=" + this.c + ", scale=" + ((Object) null) + ", hold=" + this.d + ", effectsMap=" + this.e + ')';
    }

    public /* synthetic */ q0(c0 c0Var, o0 o0Var, I i, E e, LinkedHashMap linkedHashMap, int i2) {
        this((i2 & 1) != 0 ? null : c0Var, (i2 & 2) != 0 ? null : o0Var, (i2 & 4) != 0 ? null : i, (i2 & 8) != 0 ? null : e, (i2 & 16) == 0, (i2 & 32) != 0 ? kotlin.collections.V.c() : linkedHashMap);
    }
}
