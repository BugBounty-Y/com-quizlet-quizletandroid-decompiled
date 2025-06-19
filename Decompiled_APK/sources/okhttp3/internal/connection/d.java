package okhttp3.internal.connection;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.C4937f;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.InterfaceC5077f;
import okhttp3.internal.platform.o;

/* loaded from: classes3.dex */
public final class d implements Runnable {
    public final InterfaceC5077f a;
    public volatile AtomicInteger b;
    public final /* synthetic */ g c;

    public d(g gVar, InterfaceC5077f responseCallback) {
        Intrinsics.checkNotNullParameter(responseCallback, "responseCallback");
        this.c = gVar;
        this.a = responseCallback;
        this.b = new AtomicInteger(0);
    }

    @Override // java.lang.Runnable
    public final void run() {
        com.quizlet.data.repository.explanations.exercise.b bVar;
        String str = "OkHttp " + this.c.b.a.h();
        g gVar = this.c;
        Thread threadCurrentThread = Thread.currentThread();
        String name = threadCurrentThread.getName();
        threadCurrentThread.setName(str);
        try {
            gVar.e.h();
            boolean z = false;
            try {
                try {
                    try {
                        this.a.onResponse(gVar, gVar.h());
                        bVar = gVar.a.a;
                    } catch (IOException e) {
                        e = e;
                        z = true;
                        if (z) {
                            o oVar = o.a;
                            o oVar2 = o.a;
                            String str2 = "Callback failure for " + g.b(gVar);
                            oVar2.getClass();
                            o.i(4, str2, e);
                        } else {
                            this.a.onFailure(gVar, e);
                        }
                        bVar = gVar.a.a;
                        bVar.f(this);
                    } catch (Throwable th) {
                        th = th;
                        z = true;
                        gVar.cancel();
                        if (!z) {
                            IOException iOException = new IOException("canceled due to " + th);
                            C4937f.a(iOException, th);
                            this.a.onFailure(gVar, iOException);
                        }
                        throw th;
                    }
                } catch (Throwable th2) {
                    gVar.a.a.f(this);
                    throw th2;
                }
            } catch (IOException e2) {
                e = e2;
            } catch (Throwable th3) {
                th = th3;
            }
            bVar.f(this);
        } finally {
            threadCurrentThread.setName(name);
        }
    }
}
