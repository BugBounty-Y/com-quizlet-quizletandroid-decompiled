package okio.internal;

import androidx.compose.animation.d0;
import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;
import okio.G;
import okio.o;

/* loaded from: classes3.dex */
public final class f extends o {
    public final long b;
    public final boolean c;
    public long d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(G delegate, long j, boolean z) {
        super(delegate);
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.b = j;
        this.c = z;
    }

    @Override // okio.o, okio.G
    public final long b0(C5091h sink, long j) throws IOException {
        Intrinsics.checkNotNullParameter(sink, "sink");
        long j2 = this.d;
        long j3 = this.b;
        if (j2 > j3) {
            j = 0;
        } else if (this.c) {
            long j4 = j3 - j2;
            if (j4 == 0) {
                return -1L;
            }
            j = Math.min(j, j4);
        }
        long jB0 = super.b0(sink, j);
        if (jB0 != -1) {
            this.d += jB0;
        }
        long j5 = this.d;
        if ((j5 >= j3 || jB0 != -1) && j5 <= j3) {
            return jB0;
        }
        if (jB0 > 0 && j5 > j3) {
            long j6 = sink.b - (j5 - j3);
            C5091h c5091h = new C5091h();
            c5091h.M(sink);
            sink.L(c5091h, j6);
            c5091h.d();
        }
        StringBuilder sbT = d0.t(j3, "expected ", " bytes but got ");
        sbT.append(this.d);
        throw new IOException(sbT.toString());
    }
}
