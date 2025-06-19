package kotlin;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class H implements Comparable {

    @NotNull
    public static final G b = new G(null);
    public final short a;

    public /* synthetic */ H(short s) {
        this.a = s;
    }

    @Override // java.lang.Comparable
    public final /* synthetic */ int compareTo(Object obj) {
        return Intrinsics.g(this.a & 65535, ((H) obj).a & 65535);
    }

    public final boolean equals(Object obj) {
        if (obj instanceof H) {
            return this.a == ((H) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Short.hashCode(this.a);
    }

    public final String toString() {
        return String.valueOf(65535 & this.a);
    }
}
