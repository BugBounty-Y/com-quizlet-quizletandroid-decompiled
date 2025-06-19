package com.google.firebase.perf.transport;

import android.content.Context;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.firebase.h;
import com.google.firebase.perf.v1.C3975e;
import com.google.firebase.perf.v1.E;
import com.google.firebase.perf.v1.i;
import com.google.firebase.perf.v1.o;
import com.google.firebase.perf.v1.t;
import com.google.firebase.perf.v1.v;
import com.google.firebase.perf.v1.w;
import java.text.DecimalFormat;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes2.dex */
public final class f implements com.google.firebase.perf.application.b {
    public static final com.google.firebase.perf.logging.a r = com.google.firebase.perf.logging.a.d();
    public static final f s = new f();
    public final ConcurrentHashMap a;
    public h d;
    public com.google.firebase.perf.b e;
    public com.google.firebase.installations.d f;
    public com.google.firebase.inject.b g;
    public a h;
    public Context j;
    public com.google.firebase.perf.config.a k;
    public d l;
    public com.google.firebase.perf.application.c m;
    public C3975e n;
    public String o;
    public String p;
    public final ConcurrentLinkedQueue b = new ConcurrentLinkedQueue();
    public final AtomicBoolean c = new AtomicBoolean(false);
    public boolean q = false;
    public final ThreadPoolExecutor i = new ThreadPoolExecutor(0, 1, 10, TimeUnit.SECONDS, new LinkedBlockingQueue());

    public f() {
        ConcurrentHashMap concurrentHashMap = new ConcurrentHashMap();
        this.a = concurrentHashMap;
        concurrentHashMap.put("KEY_AVAILABLE_TRACES_FOR_CACHING", 50);
        concurrentHashMap.put("KEY_AVAILABLE_NETWORK_REQUESTS_FOR_CACHING", 50);
        concurrentHashMap.put("KEY_AVAILABLE_GAUGES_FOR_CACHING", 50);
    }

    public static String a(w wVar) {
        if (wVar.c()) {
            E eD = wVar.d();
            long jK = eD.K();
            Locale locale = Locale.ENGLISH;
            return AbstractC0147y.e("trace metric: ", eD.L(), " (duration: ", new DecimalFormat("#.####").format(jK / 1000.0d), "ms)");
        }
        if (wVar.e()) {
            t tVarF = wVar.f();
            long jR = tVarF.a0() ? tVarF.R() : 0L;
            String strValueOf = tVarF.W() ? String.valueOf(tVarF.M()) : "UNKNOWN";
            Locale locale2 = Locale.ENGLISH;
            return android.support.v4.media.session.a.t(AbstractC0147y.h("network request trace: ", tVarF.T(), " (responseCode: ", strValueOf, ", responseTime: "), new DecimalFormat("#.####").format(jR / 1000.0d), "ms)");
        }
        if (!wVar.b()) {
            return "log";
        }
        o oVarG = wVar.g();
        Locale locale3 = Locale.ENGLISH;
        boolean zE = oVarG.E();
        int iB = oVarG.B();
        int iA = oVarG.A();
        StringBuilder sb = new StringBuilder("gauges (hasMetadata: ");
        sb.append(zE);
        sb.append(", cpuGaugeCount: ");
        sb.append(iB);
        sb.append(", memoryGaugeCount: ");
        return android.support.v4.media.session.a.r(sb, iA, ")");
    }

    public final void b(v vVar) {
        if (vVar.c()) {
            this.m.b("_fstec");
        } else if (vVar.e()) {
            this.m.b("_fsntc");
        }
    }

    public final void c(E e, i iVar) {
        this.i.execute(new com.facebook.login.E(this, e, iVar, 5));
    }

    /* JADX WARN: Removed duplicated region for block: B:118:0x02ec  */
    /* JADX WARN: Removed duplicated region for block: B:138:0x0344  */
    /* JADX WARN: Removed duplicated region for block: B:157:0x03be  */
    /* JADX WARN: Removed duplicated region for block: B:186:0x045e  */
    /* JADX WARN: Removed duplicated region for block: B:212:0x04e6  */
    /* JADX WARN: Removed duplicated region for block: B:243:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00f7  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x011b  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x0121  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0153  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x015b  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x018a  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x019c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(com.google.firebase.perf.v1.u r18, com.google.firebase.perf.v1.i r19) {
        /*
            Method dump skipped, instructions count: 1419
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.perf.transport.f.d(com.google.firebase.perf.v1.u, com.google.firebase.perf.v1.i):void");
    }

    @Override // com.google.firebase.perf.application.b
    public final void onUpdateAppState(i iVar) {
        this.q = iVar == i.FOREGROUND;
        if (this.c.get()) {
            this.i.execute(new e(this, 0));
        }
    }
}
