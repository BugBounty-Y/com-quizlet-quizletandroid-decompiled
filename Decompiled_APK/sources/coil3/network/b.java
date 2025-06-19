package coil3.network;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public final t a;

    public b(t tVar) {
        this.a = tVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof b) {
            return Intrinsics.b(this.a, ((b) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        t tVar = this.a;
        if (tVar != null) {
            return tVar.hashCode();
        }
        return 0;
    }

    public final String toString() {
        return "WriteResult(response=" + this.a + ')';
    }
}
