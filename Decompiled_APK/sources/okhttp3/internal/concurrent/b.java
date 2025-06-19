package okhttp3.internal.concurrent;

import com.google.android.gms.measurement.internal.J;
import com.quizlet.features.folders.composables.W;
import java.io.IOException;
import java.net.Socket;
import java.util.Iterator;
import java.util.concurrent.ConcurrentLinkedQueue;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.internal.connection.i;
import okhttp3.internal.http2.n;

/* loaded from: classes3.dex */
public final class b extends a {
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(String str, int i, Object obj) {
        super(str, true);
        this.e = i;
        this.f = obj;
    }

    @Override // okhttp3.internal.concurrent.a
    public final long a() throws Throwable {
        int i = 0;
        switch (this.e) {
            case 0:
                ((W) this.f).invoke();
                return -1L;
            case 1:
                J j = (J) this.f;
                long jNanoTime = System.nanoTime();
                Iterator it2 = ((ConcurrentLinkedQueue) j.e).iterator();
                long j2 = Long.MIN_VALUE;
                i iVar = null;
                int i2 = 0;
                while (it2.hasNext()) {
                    i connection = (i) it2.next();
                    Intrinsics.checkNotNullExpressionValue(connection, "connection");
                    synchronized (connection) {
                        if (j.h(connection, jNanoTime) > 0) {
                            i2++;
                        } else {
                            i++;
                            long j3 = jNanoTime - connection.q;
                            if (j3 > j2) {
                                iVar = connection;
                                j2 = j3;
                            }
                            Unit unit = Unit.a;
                        }
                    }
                }
                long j4 = j.b;
                if (j2 < j4 && i <= 5) {
                    if (i > 0) {
                        return j4 - j2;
                    }
                    if (i2 > 0) {
                        return j4;
                    }
                    return -1L;
                }
                Intrinsics.d(iVar);
                synchronized (iVar) {
                    if (!iVar.p.isEmpty()) {
                        return 0L;
                    }
                    if (iVar.q + j2 != jNanoTime) {
                        return 0L;
                    }
                    iVar.j = true;
                    ((ConcurrentLinkedQueue) j.e).remove(iVar);
                    Socket socket = iVar.d;
                    Intrinsics.d(socket);
                    okhttp3.internal.b.e(socket);
                    if (!((ConcurrentLinkedQueue) j.e).isEmpty()) {
                        return 0L;
                    }
                    ((c) j.c).a();
                    return 0L;
                }
            default:
                n nVar = (n) this.f;
                nVar.getClass();
                try {
                    nVar.w.l(2, 0, false);
                } catch (IOException e) {
                    nVar.d(e);
                }
                return -1L;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(J j, String str) {
        super(str, true);
        this.e = 1;
        this.f = j;
    }
}
