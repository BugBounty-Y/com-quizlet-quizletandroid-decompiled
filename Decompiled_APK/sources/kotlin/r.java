package kotlin;

import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class r implements Serializable {

    @NotNull
    public static final p b = new p(null);
    public final Object a;

    public static final Throwable a(Object obj) {
        if (obj instanceof q) {
            return ((q) obj).a;
        }
        return null;
    }

    public static String b(Object obj) {
        if (obj instanceof q) {
            return obj.toString();
        }
        return "Success(" + obj + ')';
    }

    public final boolean equals(Object obj) {
        if (obj instanceof r) {
            return Intrinsics.b(this.a, ((r) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        Object obj = this.a;
        if (obj == null) {
            return 0;
        }
        return obj.hashCode();
    }

    public final String toString() {
        return b(this.a);
    }
}
