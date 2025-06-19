package kotlinx.io;

import androidx.compose.animation.d0;
import java.io.IOException;
import java.io.InputStream;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class b implements d {
    public final InputStream a;

    public b(InputStream input) {
        Intrinsics.checkNotNullParameter(input, "input");
        this.a = input;
    }

    @Override // kotlinx.io.d
    public final long A(a sink, long j) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (j == 0) {
            return 0L;
        }
        if (j < 0) {
            throw new IllegalArgumentException(d0.o(j, "byteCount (", ") < 0").toString());
        }
        boolean z = false;
        try {
            g gVarI = sink.i(1);
            byte[] data = gVarI.a;
            long j2 = this.a.read(data, gVarI.c, (int) Math.min(j, data.length - r5));
            int i = j2 == -1 ? 0 : (int) j2;
            if (i == 1) {
                Intrinsics.checkNotNullParameter(data, "data");
                gVarI.c += i;
                sink.c += i;
                return j2;
            }
            if (i < 0 || i > gVarI.a()) {
                throw new IllegalStateException(("Invalid number of bytes written: " + i + ". Should be in 0.." + gVarI.a()).toString());
            }
            if (i != 0) {
                Intrinsics.checkNotNullParameter(data, "data");
                gVarI.c += i;
                sink.c += i;
                return j2;
            }
            if (!j.c(gVarI)) {
                return j2;
            }
            sink.d();
            return j2;
        } catch (AssertionError e) {
            Intrinsics.checkNotNullParameter(e, "<this>");
            if (e.getCause() != null) {
                String message = e.getMessage();
                if (message != null ? StringsKt.G(message, "getsockname failed", false) : false) {
                    z = true;
                }
            }
            if (z) {
                throw new IOException(e);
            }
            throw e;
        }
    }

    @Override // java.lang.AutoCloseable
    public final void close() {
        this.a.close();
    }

    public final String toString() {
        return "RawSource(" + this.a + ')';
    }
}
