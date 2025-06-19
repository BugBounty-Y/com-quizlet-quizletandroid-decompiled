package okhttp3.internal.connection;

import androidx.compose.material.ripple.r;
import androidx.constraintlayout.core.motion.utils.l;
import com.google.android.gms.measurement.internal.J;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.ref.Reference;
import java.net.Socket;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.Unit;
import kotlin.collections.G;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;
import okhttp3.C;
import okhttp3.H;
import okhttp3.InterfaceC5076e;
import okhttp3.InterfaceC5077f;
import okhttp3.o;

/* loaded from: classes3.dex */
public final class g implements InterfaceC5076e {
    public final A a;
    public final C b;
    public final boolean c;
    public final J d;
    public final f e;
    public final AtomicBoolean f;
    public Object g;
    public l h;
    public i i;
    public boolean j;
    public r k;
    public boolean l;
    public boolean m;
    public boolean n;
    public volatile boolean o;
    public volatile r p;
    public volatile i q;

    public g(A client, C originalRequest, boolean z) {
        Intrinsics.checkNotNullParameter(client, "client");
        Intrinsics.checkNotNullParameter(originalRequest, "originalRequest");
        this.a = client;
        this.b = originalRequest;
        this.c = z;
        this.d = (J) client.b.b;
        client.e.getClass();
        o this_asFactory = o.c;
        Intrinsics.checkNotNullParameter(this_asFactory, "$this_asFactory");
        Intrinsics.checkNotNullParameter(this, "it");
        f fVar = new f(this);
        fVar.g(0, TimeUnit.MILLISECONDS);
        this.e = fVar;
        this.f = new AtomicBoolean();
        this.n = true;
    }

    public static final String b(g gVar) {
        StringBuilder sb = new StringBuilder();
        sb.append(gVar.o ? "canceled " : "");
        sb.append(gVar.c ? "web socket" : "call");
        sb.append(" to ");
        sb.append(gVar.b.a.h());
        return sb.toString();
    }

    public final void c(i connection) {
        Intrinsics.checkNotNullParameter(connection, "connection");
        byte[] bArr = okhttp3.internal.b.a;
        if (this.i != null) {
            throw new IllegalStateException("Check failed.");
        }
        this.i = connection;
        connection.p.add(new e(this, this.g));
    }

    public final void cancel() {
        Socket socket;
        if (this.o) {
            return;
        }
        this.o = true;
        r rVar = this.p;
        if (rVar != null) {
            ((okhttp3.internal.http.d) rVar.d).cancel();
        }
        i iVar = this.q;
        if (iVar != null && (socket = iVar.c) != null) {
            okhttp3.internal.b.e(socket);
        }
        Intrinsics.checkNotNullParameter(this, "call");
    }

    public final Object clone() {
        return new g(this.a, this.b, this.c);
    }

    public final IOException d(IOException iOException) {
        IOException ioe;
        Socket socketL;
        byte[] bArr = okhttp3.internal.b.a;
        i connection = this.i;
        if (connection != null) {
            synchronized (connection) {
                socketL = l();
            }
            if (this.i == null) {
                if (socketL != null) {
                    okhttp3.internal.b.e(socketL);
                }
                Intrinsics.checkNotNullParameter(this, "call");
                Intrinsics.checkNotNullParameter(connection, "connection");
            } else if (socketL != null) {
                throw new IllegalStateException("Check failed.");
            }
        }
        if (!this.j && this.e.i()) {
            ioe = new InterruptedIOException("timeout");
            if (iOException != null) {
                ioe.initCause(iOException);
            }
        } else {
            ioe = iOException;
        }
        if (iOException == null) {
            Intrinsics.checkNotNullParameter(this, "call");
            return ioe;
        }
        Intrinsics.d(ioe);
        Intrinsics.checkNotNullParameter(this, "call");
        Intrinsics.checkNotNullParameter(ioe, "ioe");
        return ioe;
    }

    public final void e(InterfaceC5077f responseCallback) {
        d other;
        Intrinsics.checkNotNullParameter(responseCallback, "responseCallback");
        if (!this.f.compareAndSet(false, true)) {
            throw new IllegalStateException("Already Executed");
        }
        okhttp3.internal.platform.o oVar = okhttp3.internal.platform.o.a;
        this.g = okhttp3.internal.platform.o.a.g();
        Intrinsics.checkNotNullParameter(this, "call");
        com.quizlet.data.repository.explanations.exercise.b bVar = this.a.a;
        d call = new d(this, responseCallback);
        bVar.getClass();
        Intrinsics.checkNotNullParameter(call, "call");
        synchronized (bVar) {
            ((ArrayDeque) bVar.b).add(call);
            if (!this.c) {
                String str = this.b.a.d;
                Iterator it2 = ((ArrayDeque) bVar.c).iterator();
                while (true) {
                    if (!it2.hasNext()) {
                        Iterator it3 = ((ArrayDeque) bVar.b).iterator();
                        while (true) {
                            if (!it3.hasNext()) {
                                other = null;
                                break;
                            } else {
                                other = (d) it3.next();
                                if (Intrinsics.b(other.c.b.a.d, str)) {
                                    break;
                                }
                            }
                        }
                    } else {
                        other = (d) it2.next();
                        if (Intrinsics.b(other.c.b.a.d, str)) {
                            break;
                        }
                    }
                }
                if (other != null) {
                    Intrinsics.checkNotNullParameter(other, "other");
                    call.b = other.b;
                }
            }
            Unit unit = Unit.a;
        }
        bVar.g();
    }

    public final H f() {
        if (!this.f.compareAndSet(false, true)) {
            throw new IllegalStateException("Already Executed");
        }
        this.e.h();
        okhttp3.internal.platform.o oVar = okhttp3.internal.platform.o.a;
        this.g = okhttp3.internal.platform.o.a.g();
        Intrinsics.checkNotNullParameter(this, "call");
        try {
            com.quizlet.data.repository.explanations.exercise.b bVar = this.a.a;
            synchronized (bVar) {
                Intrinsics.checkNotNullParameter(this, "call");
                ((ArrayDeque) bVar.d).add(this);
            }
            return h();
        } finally {
            com.quizlet.data.repository.explanations.exercise.b bVar2 = this.a.a;
            bVar2.getClass();
            Intrinsics.checkNotNullParameter(this, "call");
            bVar2.e((ArrayDeque) bVar2.d, this);
        }
    }

    public final void g(boolean z) {
        r rVar;
        synchronized (this) {
            if (!this.n) {
                throw new IllegalStateException("released");
            }
            Unit unit = Unit.a;
        }
        if (z && (rVar = this.p) != null) {
            ((okhttp3.internal.http.d) rVar.d).cancel();
            ((g) rVar.b).i(rVar, true, true, null);
        }
        this.k = null;
    }

    public final H h() {
        ArrayList arrayList = new ArrayList();
        G.u(arrayList, this.a.c);
        arrayList.add(new okhttp3.internal.http.a(this.a));
        arrayList.add(new okhttp3.internal.http.a(this.a.j));
        this.a.getClass();
        arrayList.add(new okhttp3.internal.cache.b());
        arrayList.add(a.a);
        if (!this.c) {
            G.u(arrayList, this.a.d);
        }
        arrayList.add(new okhttp3.internal.http.b(this.c));
        C c = this.b;
        A a = this.a;
        boolean z = false;
        try {
            try {
                H hB = new okhttp3.internal.http.f(this, arrayList, 0, null, c, a.v, a.w, a.x).b(this.b);
                if (this.o) {
                    okhttp3.internal.b.d(hB);
                    throw new IOException("Canceled");
                }
                k(null);
                return hB;
            } catch (IOException e) {
                z = true;
                IOException iOExceptionK = k(e);
                Intrinsics.e(iOExceptionK, "null cannot be cast to non-null type kotlin.Throwable");
                throw iOExceptionK;
            }
        } catch (Throwable th) {
            if (!z) {
                k(null);
            }
            throw th;
        }
    }

    public final IOException i(r exchange, boolean z, boolean z2, IOException iOException) {
        boolean z3;
        boolean z4;
        Intrinsics.checkNotNullParameter(exchange, "exchange");
        if (Intrinsics.b(exchange, this.p)) {
            synchronized (this) {
                z3 = false;
                if (z) {
                    try {
                        if (!this.l) {
                            if (z2 || !this.m) {
                                z4 = false;
                            }
                            Unit unit = Unit.a;
                        }
                        if (z) {
                            this.l = false;
                        }
                        if (z2) {
                            this.m = false;
                        }
                        boolean z5 = this.l;
                        boolean z6 = (z5 || this.m) ? false : true;
                        if (!z5 && !this.m && !this.n) {
                            z3 = true;
                        }
                        z4 = z3;
                        z3 = z6;
                        Unit unit2 = Unit.a;
                    } catch (Throwable th) {
                        throw th;
                    }
                } else {
                    if (z2) {
                    }
                    z4 = false;
                    Unit unit22 = Unit.a;
                }
            }
            if (z3) {
                this.p = null;
                i iVar = this.i;
                if (iVar != null) {
                    synchronized (iVar) {
                        iVar.m++;
                    }
                }
            }
            if (z4) {
                return d(iOException);
            }
        }
        return iOException;
    }

    public final IOException k(IOException iOException) {
        boolean z;
        synchronized (this) {
            try {
                z = false;
                if (this.n) {
                    this.n = false;
                    if (!this.l && !this.m) {
                        z = true;
                    }
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
        return z ? d(iOException) : iOException;
    }

    public final Socket l() {
        i connection = this.i;
        Intrinsics.d(connection);
        byte[] bArr = okhttp3.internal.b.a;
        ArrayList arrayList = connection.p;
        Iterator it2 = arrayList.iterator();
        int i = 0;
        while (true) {
            if (!it2.hasNext()) {
                i = -1;
                break;
            }
            if (Intrinsics.b(((Reference) it2.next()).get(), this)) {
                break;
            }
            i++;
        }
        if (i == -1) {
            throw new IllegalStateException("Check failed.");
        }
        arrayList.remove(i);
        this.i = null;
        if (!arrayList.isEmpty()) {
            return null;
        }
        connection.q = System.nanoTime();
        J j = this.d;
        j.getClass();
        Intrinsics.checkNotNullParameter(connection, "connection");
        byte[] bArr2 = okhttp3.internal.b.a;
        boolean z = connection.j;
        okhttp3.internal.concurrent.c cVar = (okhttp3.internal.concurrent.c) j.c;
        if (!z) {
            cVar.c((okhttp3.internal.concurrent.b) j.d, 0L);
            return null;
        }
        connection.j = true;
        ConcurrentLinkedQueue concurrentLinkedQueue = (ConcurrentLinkedQueue) j.e;
        concurrentLinkedQueue.remove(connection);
        if (concurrentLinkedQueue.isEmpty()) {
            cVar.a();
        }
        Socket socket = connection.d;
        Intrinsics.d(socket);
        return socket;
    }
}
