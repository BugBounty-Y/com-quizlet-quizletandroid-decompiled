package kotlinx.coroutines.channels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m extends n {
    public final Throwable a;

    public m(Throwable th) {
        this.a = th;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof m) {
            return Intrinsics.b(this.a, ((m) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        Throwable th = this.a;
        if (th != null) {
            return th.hashCode();
        }
        return 0;
    }

    @Override // kotlinx.coroutines.channels.n
    public final String toString() {
        return "Closed(" + this.a + ')';
    }
}
