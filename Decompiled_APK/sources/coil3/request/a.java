package coil3.request;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class a implements n {
    public final InterfaceC5025j0 a;

    public /* synthetic */ a(InterfaceC5025j0 interfaceC5025j0) {
        this.a = interfaceC5025j0;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof a) {
            return Intrinsics.b(this.a, ((a) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "BaseRequestDelegate(job=" + this.a + ')';
    }
}
