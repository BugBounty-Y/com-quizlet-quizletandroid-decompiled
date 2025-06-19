package io.ktor.util.reflect;

import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.U;

/* loaded from: classes3.dex */
public final class a {
    public final C4950i a;
    public final U b;

    public a(C4950i type, U u) {
        Intrinsics.checkNotNullParameter(type, "type");
        this.a = type;
        this.b = u;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        U u = this.b;
        if (u == null) {
            a aVar = (a) obj;
            if (aVar.b == null) {
                return this.a.equals(aVar.a);
            }
        }
        return Intrinsics.b(u, ((a) obj).b);
    }

    public final int hashCode() {
        U u = this.b;
        return u != null ? u.hashCode() : this.a.hashCode();
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TypeInfo(");
        Object obj = this.b;
        if (obj == null) {
            obj = this.a;
        }
        sb.append(obj);
        sb.append(')');
        return sb.toString();
    }
}
