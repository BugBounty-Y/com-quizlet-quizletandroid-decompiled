package okhttp3.internal.concurrent;

import com.google.android.gms.common.api.internal.w;
import com.pubmatic.sdk.video.c;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.logging.Logger;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public static final d h;
    public static final Logger i;
    public final com.quizlet.login.authentication.login.a a;
    public int b;
    public boolean c;
    public long d;
    public final ArrayList e;
    public final ArrayList f;
    public final w g;

    static {
        String name = okhttp3.internal.b.g + " TaskRunner";
        Intrinsics.checkNotNullParameter(name, "name");
        h = new d(new com.quizlet.login.authentication.login.a(new okhttp3.internal.a(name, true)));
        Logger logger = Logger.getLogger(d.class.getName());
        Intrinsics.checkNotNullExpressionValue(logger, "getLogger(TaskRunner::class.java.name)");
        i = logger;
    }

    public d(com.quizlet.login.authentication.login.a backend) {
        Intrinsics.checkNotNullParameter(backend, "backend");
        this.a = backend;
        this.b = c.a.DEFAULT_MEDIA_URI_TIMEOUT;
        this.e = new ArrayList();
        this.f = new ArrayList();
        this.g = new w(this, 23);
    }

    public static final void a(d dVar, a aVar) {
        dVar.getClass();
        byte[] bArr = okhttp3.internal.b.a;
        Thread threadCurrentThread = Thread.currentThread();
        String name = threadCurrentThread.getName();
        threadCurrentThread.setName(aVar.a);
        try {
            long jA = aVar.a();
            synchronized (dVar) {
                dVar.b(aVar, jA);
                Unit unit = Unit.a;
            }
            threadCurrentThread.setName(name);
        } catch (Throwable th) {
            synchronized (dVar) {
                dVar.b(aVar, -1L);
                Unit unit2 = Unit.a;
                threadCurrentThread.setName(name);
                throw th;
            }
        }
    }

    public final void b(a aVar, long j) {
        byte[] bArr = okhttp3.internal.b.a;
        c cVar = aVar.c;
        Intrinsics.d(cVar);
        if (cVar.d != aVar) {
            throw new IllegalStateException("Check failed.");
        }
        boolean z = cVar.f;
        cVar.f = false;
        cVar.d = null;
        this.e.remove(cVar);
        if (j != -1 && !z && !cVar.c) {
            cVar.d(aVar, j, true);
        }
        if (cVar.e.isEmpty()) {
            return;
        }
        this.f.add(cVar);
    }

    public final a c() {
        long j;
        a aVar;
        boolean z;
        byte[] bArr = okhttp3.internal.b.a;
        while (true) {
            ArrayList arrayList = this.f;
            if (arrayList.isEmpty()) {
                return null;
            }
            com.quizlet.login.authentication.login.a aVar2 = this.a;
            long jNanoTime = System.nanoTime();
            Iterator it2 = arrayList.iterator();
            long jMin = Long.MAX_VALUE;
            a aVar3 = null;
            while (true) {
                if (!it2.hasNext()) {
                    j = jNanoTime;
                    aVar = null;
                    z = false;
                    break;
                }
                a aVar4 = (a) ((c) it2.next()).e.get(0);
                j = jNanoTime;
                aVar = null;
                long jMax = Math.max(0L, aVar4.d - j);
                if (jMax > 0) {
                    jMin = Math.min(jMax, jMin);
                } else {
                    if (aVar3 != null) {
                        z = true;
                        break;
                    }
                    aVar3 = aVar4;
                }
                jNanoTime = j;
            }
            ArrayList arrayList2 = this.e;
            if (aVar3 != null) {
                byte[] bArr2 = okhttp3.internal.b.a;
                aVar3.d = -1L;
                c cVar = aVar3.c;
                Intrinsics.d(cVar);
                cVar.e.remove(aVar3);
                arrayList.remove(cVar);
                cVar.d = aVar3;
                arrayList2.add(cVar);
                if (z || (!this.c && !arrayList.isEmpty())) {
                    w runnable = this.g;
                    Intrinsics.checkNotNullParameter(runnable, "runnable");
                    ((ThreadPoolExecutor) aVar2.b).execute(runnable);
                }
                return aVar3;
            }
            if (this.c) {
                if (jMin >= this.d - j) {
                    return aVar;
                }
                Intrinsics.checkNotNullParameter(this, "taskRunner");
                notify();
                return aVar;
            }
            this.c = true;
            this.d = j + jMin;
            try {
                try {
                    Intrinsics.checkNotNullParameter(this, "taskRunner");
                    long j2 = jMin / 1000000;
                    long j3 = jMin - (1000000 * j2);
                    if (j2 > 0 || jMin > 0) {
                        wait(j2, (int) j3);
                    }
                } catch (InterruptedException unused) {
                    for (int size = arrayList2.size() - 1; -1 < size; size--) {
                        ((c) arrayList2.get(size)).b();
                    }
                    for (int size2 = arrayList.size() - 1; -1 < size2; size2--) {
                        c cVar2 = (c) arrayList.get(size2);
                        cVar2.b();
                        if (cVar2.e.isEmpty()) {
                            arrayList.remove(size2);
                        }
                    }
                }
            } finally {
                this.c = false;
            }
        }
    }

    public final void d(c taskQueue) {
        Intrinsics.checkNotNullParameter(taskQueue, "taskQueue");
        byte[] bArr = okhttp3.internal.b.a;
        if (taskQueue.d == null) {
            boolean zIsEmpty = taskQueue.e.isEmpty();
            ArrayList arrayList = this.f;
            if (zIsEmpty) {
                arrayList.remove(taskQueue);
            } else {
                Intrinsics.checkNotNullParameter(arrayList, "<this>");
                if (!arrayList.contains(taskQueue)) {
                    arrayList.add(taskQueue);
                }
            }
        }
        boolean z = this.c;
        com.quizlet.login.authentication.login.a aVar = this.a;
        if (z) {
            Intrinsics.checkNotNullParameter(this, "taskRunner");
            notify();
        } else {
            w runnable = this.g;
            Intrinsics.checkNotNullParameter(runnable, "runnable");
            ((ThreadPoolExecutor) aVar.b).execute(runnable);
        }
    }

    public final c e() {
        int i2;
        synchronized (this) {
            i2 = this.b;
            this.b = i2 + 1;
        }
        return new c(this, android.support.v4.media.session.a.f(i2, "Q"));
    }
}
