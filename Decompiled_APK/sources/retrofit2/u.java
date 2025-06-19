package retrofit2;

import androidx.recyclerview.widget.C1372j;
import androidx.transition.C1412o;
import com.google.firebase.perf.network.FirebasePerfOkHttpClient;
import java.io.IOException;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.InterfaceC5075d;
import okhttp3.InterfaceC5076e;

/* loaded from: classes3.dex */
public final class u implements InterfaceC5179d {
    public final J a;
    public final Object b;
    public final Object[] c;
    public final InterfaceC5075d d;
    public final InterfaceC5186k e;
    public volatile boolean f;
    public okhttp3.internal.connection.g g;
    public Throwable h;
    public boolean i;

    public u(J j, Object obj, Object[] objArr, InterfaceC5075d interfaceC5075d, InterfaceC5186k interfaceC5186k) {
        this.a = j;
        this.b = obj;
        this.c = objArr;
        this.d = interfaceC5075d;
        this.e = interfaceC5186k;
    }

    @Override // retrofit2.InterfaceC5179d
    public final boolean C() {
        boolean z = true;
        if (this.f) {
            return true;
        }
        synchronized (this) {
            okhttp3.internal.connection.g gVar = this.g;
            if (gVar == null || !gVar.o) {
                z = false;
            }
        }
        return z;
    }

    @Override // retrofit2.InterfaceC5179d
    public final synchronized okhttp3.C Q() {
        try {
        } catch (IOException e) {
            throw new RuntimeException("Unable to create request.", e);
        }
        return ((okhttp3.internal.connection.g) c()).b;
    }

    @Override // retrofit2.InterfaceC5179d
    public final K a() {
        InterfaceC5076e interfaceC5076eC;
        synchronized (this) {
            if (this.i) {
                throw new IllegalStateException("Already executed.");
            }
            this.i = true;
            interfaceC5076eC = c();
        }
        if (this.f) {
            ((okhttp3.internal.connection.g) interfaceC5076eC).cancel();
        }
        return d(FirebasePerfOkHttpClient.execute(interfaceC5076eC));
    }

    public final okhttp3.internal.connection.g b() {
        okhttp3.s url;
        J j = this.a;
        Object[] objArr = this.c;
        int length = objArr.length;
        S[] sArr = j.k;
        if (length != sArr.length) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.r(android.support.v4.media.session.a.v(length, "Argument count (", ") doesn't match expected count ("), sArr.length, ")"));
        }
        H h = new H(j.d, j.c, j.e, j.f, j.g, j.h, j.i, j.j);
        if (j.l) {
            length--;
        }
        ArrayList arrayList = new ArrayList(length);
        for (int i = 0; i < length; i++) {
            arrayList.add(objArr[i]);
            sArr[i].a(h, objArr[i]);
        }
        C1372j c1372j = h.d;
        if (c1372j != null) {
            url = c1372j.d();
        } else {
            String str = h.c;
            okhttp3.s sVar = h.b;
            url = sVar.i(str);
            if (url == null) {
                throw new IllegalArgumentException("Malformed URL. Base: " + sVar + ", Relative: " + h.c);
            }
        }
        okhttp3.F d = h.k;
        if (d == null) {
            com.quizlet.remote.model.user.a aVar = h.j;
            if (aVar != null) {
                d = new okhttp3.p((ArrayList) aVar.a, (ArrayList) aVar.b);
            } else {
                com.quizlet.data.interactor.set.c cVar = h.i;
                if (cVar != null) {
                    d = cVar.k();
                } else if (h.h) {
                    byte[] content = new byte[0];
                    Intrinsics.checkNotNullParameter(content, "content");
                    Intrinsics.checkNotNullParameter(content, "content");
                    d = C1412o.e(0, null, content);
                }
            }
        }
        okhttp3.w wVar = h.g;
        com.android.billingclient.api.h hVar = h.f;
        if (wVar != null) {
            if (d != null) {
                d = new okhttp3.D(d, wVar);
            } else {
                hVar.a("Content-Type", wVar.a);
            }
        }
        com.quizlet.remote.model.notes.e eVar = h.e;
        eVar.getClass();
        Intrinsics.checkNotNullParameter(url, "url");
        eVar.b = url;
        okhttp3.r headers = hVar.d();
        Intrinsics.checkNotNullParameter(headers, "headers");
        eVar.d = headers.e();
        eVar.n(h.a, d);
        eVar.q(C5191p.class, new C5191p(j.a, this.b, j.b, arrayList));
        return ((okhttp3.A) this.d).c(eVar.i());
    }

    public final InterfaceC5076e c() throws IOException {
        okhttp3.internal.connection.g gVar = this.g;
        if (gVar != null) {
            return gVar;
        }
        Throwable th = this.h;
        if (th != null) {
            if (th instanceof IOException) {
                throw ((IOException) th);
            }
            if (th instanceof RuntimeException) {
                throw ((RuntimeException) th);
            }
            throw ((Error) th);
        }
        try {
            okhttp3.internal.connection.g gVarB = b();
            this.g = gVarB;
            return gVarB;
        } catch (IOException | Error | RuntimeException e) {
            S.t(e);
            this.h = e;
            throw e;
        }
    }

    @Override // retrofit2.InterfaceC5179d
    public final void cancel() {
        okhttp3.internal.connection.g gVar;
        this.f = true;
        synchronized (this) {
            gVar = this.g;
        }
        if (gVar != null) {
            gVar.cancel();
        }
    }

    public final Object clone() {
        return new u(this.a, this.b, this.c, this.d, this.e);
    }

    public final K d(okhttp3.H h) throws IOException {
        okhttp3.J j = h.g;
        okhttp3.G gF = h.f();
        gF.g = new t(j.d(), j.a());
        okhttp3.H hA = gF.a();
        int i = hA.d;
        if (i < 200 || i >= 300) {
            try {
                okhttp3.I iD = S.d(j);
                if (hA.d()) {
                    throw new IllegalArgumentException("rawResponse should not be successful response");
                }
                return new K(hA, null, iD);
            } finally {
                j.close();
            }
        }
        if (i == 204 || i == 205) {
            j.close();
            if (hA.d()) {
                return new K(hA, null, null);
            }
            throw new IllegalArgumentException("rawResponse must be successful response");
        }
        C5193s c5193s = new C5193s(j);
        try {
            Object objConvert = this.e.convert(c5193s);
            if (hA.d()) {
                return new K(hA, objConvert, null);
            }
            throw new IllegalArgumentException("rawResponse must be successful response");
        } catch (RuntimeException e) {
            IOException iOException = c5193s.c;
            if (iOException == null) {
                throw e;
            }
            throw iOException;
        }
    }

    @Override // retrofit2.InterfaceC5179d
    public final void j(InterfaceC5182g interfaceC5182g) {
        okhttp3.internal.connection.g gVar;
        Throwable th;
        synchronized (this) {
            try {
                if (this.i) {
                    throw new IllegalStateException("Already executed.");
                }
                this.i = true;
                gVar = this.g;
                th = this.h;
                if (gVar == null && th == null) {
                    try {
                        okhttp3.internal.connection.g gVarB = b();
                        this.g = gVarB;
                        gVar = gVarB;
                    } catch (Throwable th2) {
                        th = th2;
                        S.t(th);
                        this.h = th;
                    }
                }
            } catch (Throwable th3) {
                throw th3;
            }
        }
        if (th != null) {
            interfaceC5182g.f(this, th);
            return;
        }
        if (this.f) {
            gVar.cancel();
        }
        FirebasePerfOkHttpClient.enqueue(gVar, new com.quizlet.remote.model.school.h(this, interfaceC5182g));
    }

    @Override // retrofit2.InterfaceC5179d
    /* renamed from: clone */
    public final InterfaceC5179d mo151clone() {
        return new u(this.a, this.b, this.c, this.d, this.e);
    }
}
