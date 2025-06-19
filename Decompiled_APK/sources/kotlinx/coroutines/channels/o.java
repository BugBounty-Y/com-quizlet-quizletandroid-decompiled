package kotlinx.coroutines.channels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o {
    public static final n b = new n();
    public final Object a;

    public static final Throwable a(Object obj) {
        m mVar = obj instanceof m ? (m) obj : null;
        if (mVar != null) {
            return mVar.a;
        }
        return null;
    }

    public static final Object b(Object obj) {
        if (obj instanceof n) {
            return null;
        }
        return obj;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof o) {
            return Intrinsics.b(this.a, ((o) obj).a);
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
        Object obj = this.a;
        if (obj instanceof m) {
            return ((m) obj).toString();
        }
        return "Value(" + obj + ')';
    }
}
