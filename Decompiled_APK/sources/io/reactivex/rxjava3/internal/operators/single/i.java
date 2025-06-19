package io.reactivex.rxjava3.internal.operators.single;

import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.C;
import okhttp3.G;
import okhttp3.H;
import okhttp3.InterfaceC5076e;
import okhttp3.InterfaceC5077f;
import okhttp3.J;
import okhttp3.w;

/* loaded from: classes3.dex */
public final class i implements io.reactivex.rxjava3.core.h, okhttp3.sse.a, InterfaceC5077f {
    public final Object a;
    public Object b;

    public i(C request, okhttp3.sse.b listener) {
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.a = listener;
    }

    @Override // io.reactivex.rxjava3.core.h
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.c((io.reactivex.rxjava3.internal.operators.maybe.i) this.a, bVar);
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onComplete() {
        ((io.reactivex.rxjava3.core.h) this.b).onComplete();
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onError(Throwable th) {
        ((io.reactivex.rxjava3.core.h) this.b).onError(th);
    }

    @Override // okhttp3.InterfaceC5077f
    public void onFailure(InterfaceC5076e call, IOException e) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(e, "e");
        ((okhttp3.sse.b) this.a).onFailure(this, e, null);
    }

    @Override // okhttp3.InterfaceC5077f
    public void onResponse(InterfaceC5076e call, H response) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(response, "response");
        Intrinsics.checkNotNullParameter(response, "response");
        try {
            boolean zD = response.d();
            okhttp3.sse.b bVar = (okhttp3.sse.b) this.a;
            if (!zD) {
                bVar.onFailure(this, null, response);
                response.close();
                return;
            }
            J j = response.g;
            Intrinsics.d(j);
            w wVarD = j.d();
            if (wVarD != null && Intrinsics.b(wVarD.b, "text") && Intrinsics.b(wVarD.c, "event-stream")) {
                okhttp3.internal.connection.g gVar = (okhttp3.internal.connection.g) this.b;
                if (gVar == null) {
                    Intrinsics.m("call");
                    throw null;
                }
                if (gVar.j) {
                    throw new IllegalStateException("Check failed.");
                }
                gVar.j = true;
                gVar.e.i();
                G gF = response.f();
                gF.g = okhttp3.internal.b.c;
                H hA = gF.a();
                okhttp3.internal.sse.a aVar = new okhttp3.internal.sse.a(j.f0(), this);
                try {
                    bVar.onOpen(this, hA);
                    do {
                    } while (aVar.a());
                    bVar.onClosed(this);
                    Unit unit = Unit.a;
                    response.close();
                    return;
                } catch (Exception e) {
                    bVar.onFailure(this, e, hA);
                    response.close();
                    return;
                }
            }
            bVar.onFailure(this, new IllegalStateException("Invalid content-type: " + j.d()), response);
            response.close();
        } finally {
        }
    }

    @Override // io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((io.reactivex.rxjava3.core.h) this.b).onSuccess(obj);
    }

    public i(io.reactivex.rxjava3.internal.operators.maybe.i iVar, io.reactivex.rxjava3.core.h hVar) {
        this.a = iVar;
        this.b = hVar;
    }
}
