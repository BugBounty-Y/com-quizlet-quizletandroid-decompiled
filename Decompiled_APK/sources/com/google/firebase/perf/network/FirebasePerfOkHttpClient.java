package com.google.firebase.perf.network;

import androidx.annotation.Keep;
import com.google.firebase.perf.util.Timer;
import java.io.IOException;
import okhttp3.C;
import okhttp3.F;
import okhttp3.H;
import okhttp3.InterfaceC5076e;
import okhttp3.InterfaceC5077f;
import okhttp3.J;
import okhttp3.s;
import okhttp3.w;

/* loaded from: classes2.dex */
public class FirebasePerfOkHttpClient {
    public static void a(H h, com.google.firebase.perf.metrics.d dVar, long j, long j2) {
        C c = h.a;
        if (c == null) {
            return;
        }
        dVar.l(c.a.k().toString());
        dVar.c(c.b);
        F f = c.d;
        if (f != null) {
            long jA = f.a();
            if (jA != -1) {
                dVar.f(jA);
            }
        }
        J j3 = h.g;
        if (j3 != null) {
            long jA2 = j3.a();
            if (jA2 != -1) {
                dVar.i(jA2);
            }
            w wVarD = j3.d();
            if (wVarD != null) {
                dVar.h(wVarD.a);
            }
        }
        dVar.d(h.d);
        dVar.g(j);
        dVar.j(j2);
        dVar.b();
    }

    @Keep
    public static void enqueue(InterfaceC5076e interfaceC5076e, InterfaceC5077f interfaceC5077f) {
        Timer timer = new Timer();
        okhttp3.internal.connection.g gVar = (okhttp3.internal.connection.g) interfaceC5076e;
        gVar.e(new com.google.android.gms.measurement.internal.J(interfaceC5077f, com.google.firebase.perf.transport.f.s, timer, timer.a));
    }

    @Keep
    public static H execute(InterfaceC5076e interfaceC5076e) throws IOException {
        com.google.firebase.perf.metrics.d dVar = new com.google.firebase.perf.metrics.d(com.google.firebase.perf.transport.f.s);
        Timer timer = new Timer();
        long j = timer.a;
        try {
            H hF = ((okhttp3.internal.connection.g) interfaceC5076e).f();
            a(hF, dVar, j, timer.a());
            return hF;
        } catch (IOException e) {
            C c = ((okhttp3.internal.connection.g) interfaceC5076e).b;
            if (c != null) {
                s sVar = c.a;
                if (sVar != null) {
                    dVar.l(sVar.k().toString());
                }
                String str = c.b;
                if (str != null) {
                    dVar.c(str);
                }
            }
            dVar.g(j);
            dVar.j(timer.a());
            g.c(dVar);
            throw e;
        }
    }
}
