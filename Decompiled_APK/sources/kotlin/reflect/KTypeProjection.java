package kotlin.reflect;

import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.U;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class KTypeProjection {

    @NotNull
    public static final q c = new q(null);
    public static final KTypeProjection d = new KTypeProjection(null, null);
    public final s a;
    public final U b;

    public KTypeProjection(s sVar, U u) {
        String str;
        this.a = sVar;
        this.b = u;
        if ((sVar == null) == (u == null)) {
            return;
        }
        if (sVar == null) {
            str = "Star projection must have no type specified.";
        } else {
            str = "The projection variance " + sVar + " requires type to be specified.";
        }
        throw new IllegalArgumentException(str.toString());
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof KTypeProjection)) {
            return false;
        }
        KTypeProjection kTypeProjection = (KTypeProjection) obj;
        return this.a == kTypeProjection.a && Intrinsics.b(this.b, kTypeProjection.b);
    }

    public final int hashCode() {
        s sVar = this.a;
        int iHashCode = (sVar == null ? 0 : sVar.hashCode()) * 31;
        U u = this.b;
        return iHashCode + (u != null ? u.hashCode() : 0);
    }

    public final String toString() {
        s sVar = this.a;
        int i = sVar == null ? -1 : r.a[sVar.ordinal()];
        if (i == -1) {
            return "*";
        }
        U u = this.b;
        if (i == 1) {
            return String.valueOf(u);
        }
        if (i == 2) {
            return "in " + u;
        }
        if (i != 3) {
            throw new NoWhenBranchMatchedException();
        }
        return "out " + u;
    }
}
