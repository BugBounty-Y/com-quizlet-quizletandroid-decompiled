package io.ktor.utils.io;

import com.google.android.gms.internal.mlkit_vision_barcode.u7;
import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z implements n {
    public final kotlinx.io.a b;
    private volatile x closed;

    public z(kotlinx.io.a source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.b = source;
    }

    @Override // io.ktor.utils.io.n
    public final void b(Throwable th) {
        if (this.closed != null) {
            return;
        }
        String message = th.getMessage();
        if (message == null) {
            message = "Channel was cancelled";
        }
        this.closed = new x(new IOException(message, th));
    }

    @Override // io.ktor.utils.io.n
    public final Throwable c() {
        x xVar = this.closed;
        if (xVar != null) {
            return xVar.a();
        }
        return null;
    }

    @Override // io.ktor.utils.io.n
    public final kotlinx.io.i d() throws Throwable {
        Throwable thC = c();
        if (thC == null) {
            return this.b;
        }
        throw thC;
    }

    @Override // io.ktor.utils.io.n
    public final Object e(int i, kotlin.coroutines.jvm.internal.c cVar) throws Throwable {
        Throwable thC = c();
        if (thC == null) {
            return Boolean.valueOf(u7.c(this.b) >= ((long) 1));
        }
        throw thC;
    }

    @Override // io.ktor.utils.io.n
    public final boolean f() {
        return this.b.u();
    }
}
