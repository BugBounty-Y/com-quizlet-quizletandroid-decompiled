package kotlin;

import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q implements Serializable {
    public final Throwable a;

    public q(Throwable exception) {
        Intrinsics.checkNotNullParameter(exception, "exception");
        this.a = exception;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof q) {
            return Intrinsics.b(this.a, ((q) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Failure(" + this.a + ')';
    }
}
