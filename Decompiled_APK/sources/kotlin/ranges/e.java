package kotlin.ranges;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class e extends b {

    @NotNull
    public static final d e = new d(null);

    static {
        new e((char) 1, (char) 0);
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof e)) {
            return false;
        }
        char c = this.a;
        char c2 = this.b;
        if (Intrinsics.g(c, c2) > 0) {
            e eVar = (e) obj;
            if (Intrinsics.g(eVar.a, eVar.b) > 0) {
                return true;
            }
        }
        e eVar2 = (e) obj;
        return c == eVar2.a && c2 == eVar2.b;
    }

    public final int hashCode() {
        char c = this.a;
        char c2 = this.b;
        if (Intrinsics.g(c, c2) > 0) {
            return -1;
        }
        return (c * 31) + c2;
    }

    public final String toString() {
        return this.a + ".." + this.b;
    }
}
