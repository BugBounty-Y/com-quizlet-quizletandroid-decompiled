package androidx.navigation;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.navigation.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1289k {
    public final S a;
    public final boolean b;
    public final boolean c;
    public final boolean d;
    public final Object e;

    public C1289k(S type, boolean z, Object obj, boolean z2, boolean z3) {
        Intrinsics.checkNotNullParameter(type, "type");
        if (!type.a && z) {
            throw new IllegalArgumentException((type.b() + " does not allow nullable values").toString());
        }
        if (!z && z2 && obj == null) {
            throw new IllegalArgumentException(("Argument with type " + type.b() + " has null value but is not nullable.").toString());
        }
        this.a = type;
        this.b = z;
        this.e = obj;
        this.c = z2 || z3;
        this.d = z3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C1289k.class == obj.getClass()) {
            C1289k c1289k = (C1289k) obj;
            if (this.b != c1289k.b || this.c != c1289k.c || !Intrinsics.b(this.a, c1289k.a)) {
                return false;
            }
            Object obj2 = c1289k.e;
            Object obj3 = this.e;
            if (obj3 != null) {
                return Intrinsics.b(obj3, obj2);
            }
            if (obj2 == null) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = ((((this.a.hashCode() * 31) + (this.b ? 1 : 0)) * 31) + (this.c ? 1 : 0)) * 31;
        Object obj = this.e;
        return iHashCode + (obj != null ? obj.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(kotlin.jvm.internal.K.a(C1289k.class).f());
        sb.append(" Type: " + this.a);
        sb.append(" Nullable: " + this.b);
        if (this.c) {
            sb.append(" DefaultValue: " + this.e);
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }
}
