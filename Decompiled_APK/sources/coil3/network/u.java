package coil3.network;

import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;
import okio.InterfaceC5093j;

/* loaded from: classes.dex */
public final class u implements AutoCloseable {
    public final InterfaceC5093j a;

    @Override // java.lang.AutoCloseable
    public final void close() throws IOException {
        this.a.close();
    }

    public final boolean equals(Object obj) {
        if (obj instanceof u) {
            return Intrinsics.b(this.a, ((u) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SourceResponseBody(source=" + this.a + ')';
    }
}
