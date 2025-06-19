package okhttp3.internal.http2;

import java.net.SocketTimeoutException;
import kotlin.Unit;
import okio.C5088e;

/* loaded from: classes3.dex */
public final class u extends C5088e {
    public final /* synthetic */ v m;

    public u(v vVar) {
        this.m = vVar;
    }

    @Override // okio.C5088e
    public final void j() {
        this.m.e(a.CANCEL);
        n nVar = this.m.b;
        synchronized (nVar) {
            long j = nVar.n;
            long j2 = nVar.m;
            if (j < j2) {
                return;
            }
            nVar.m = j2 + 1;
            nVar.o = System.nanoTime() + 1000000000;
            Unit unit = Unit.a;
            nVar.h.c(new okhttp3.internal.concurrent.b(android.support.v4.media.session.a.t(new StringBuilder(), nVar.c, " ping"), 2, nVar), 0L);
        }
    }

    public final void k() {
        if (i()) {
            throw new SocketTimeoutException("timeout");
        }
    }
}
