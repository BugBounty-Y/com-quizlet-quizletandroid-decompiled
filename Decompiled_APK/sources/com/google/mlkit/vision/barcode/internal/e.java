package com.google.mlkit.vision.barcode.internal;

import android.os.SystemClock;
import androidx.appcompat.app.ExecutorC0060p;
import androidx.appcompat.app.Q;
import androidx.browser.customtabs.k;
import androidx.compose.foundation.gestures.l1;
import com.google.android.gms.common.internal.MethodInvocation;
import com.google.android.gms.common.internal.TelemetryData;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.C2824xF;
import com.google.android.gms.internal.ads.RunnableC1782Ud;
import com.google.android.gms.internal.ads.RunnableC1788Vd;
import com.google.android.gms.internal.mlkit_vision_barcode.C3268u;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3290w5;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3298x5;
import com.google.android.gms.internal.mlkit_vision_barcode.G5;
import com.google.android.gms.internal.mlkit_vision_barcode.H5;
import com.google.android.gms.internal.mlkit_vision_barcode.J7;
import com.google.android.gms.internal.mlkit_vision_barcode.W;
import com.google.android.gms.tasks.m;
import com.google.mlkit.common.MlKitException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/* loaded from: classes2.dex */
public final class e {
    public static boolean j = true;
    public final com.google.mlkit.vision.barcode.b d;
    public final f e;
    public final J7 f;
    public final com.quizlet.data.interactor.school.b g;
    public boolean i;
    public final AtomicInteger b = new AtomicInteger(0);
    public final AtomicBoolean c = new AtomicBoolean(false);
    public final k a = new k(14, false);
    public final com.google.mlkit.vision.common.internal.a h = new com.google.mlkit.vision.common.internal.a();

    public e(com.google.mlkit.common.sdkinternal.f fVar, com.google.mlkit.vision.barcode.b bVar, f fVar2, J7 j7) {
        u.i(fVar, "MlKitContext can not be null");
        u.i(bVar, "BarcodeScannerOptions can not be null");
        this.d = bVar;
        this.e = fVar2;
        this.f = j7;
        this.g = new com.quizlet.data.interactor.school.b(fVar.b());
    }

    public final m a(Executor executor, Callable callable, Q q) {
        u.k(this.b.get() > 0);
        if (((m) q.a).k()) {
            m mVar = new m();
            mVar.s();
            return mVar;
        }
        com.google.firebase.platforminfo.c cVar = new com.google.firebase.platforminfo.c(24);
        com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f((Q) cVar.a);
        this.a.j(new RunnableC1788Vd(this, q, cVar, callable, fVar, 6), new ExecutorC0060p(executor, q, cVar, fVar));
        return fVar.a;
    }

    public final List b(com.google.mlkit.vision.common.a aVar) throws Throwable {
        e eVar;
        com.google.mlkit.vision.common.a aVar2;
        synchronized (this) {
            try {
                try {
                    com.google.mlkit.vision.common.internal.a aVar3 = this.h;
                    long jElapsedRealtime = SystemClock.elapsedRealtime();
                    aVar3.a(aVar);
                    try {
                        ArrayList arrayListB = this.e.b(aVar);
                        eVar = this;
                        aVar2 = aVar;
                        try {
                            eVar.c(EnumC3290w5.NO_ERROR, jElapsedRealtime, aVar2, arrayListB);
                            j = false;
                            return arrayListB;
                        } catch (MlKitException e) {
                            e = e;
                            MlKitException mlKitException = e;
                            eVar.c(mlKitException.a == 14 ? EnumC3290w5.MODEL_NOT_DOWNLOADED : EnumC3290w5.UNKNOWN_ERROR, jElapsedRealtime, aVar2, null);
                            throw mlKitException;
                        }
                    } catch (MlKitException e2) {
                        e = e2;
                        eVar = this;
                        aVar2 = aVar;
                    }
                } catch (Throwable th) {
                    th = th;
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
            }
        }
    }

    public final void c(EnumC3290w5 enumC3290w5, long j2, com.google.mlkit.vision.common.a aVar, List list) {
        C3268u c3268u = new C3268u(0);
        C3268u c3268u2 = new C3268u(0);
        if (list != null) {
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                com.google.mlkit.vision.barcode.common.a aVar2 = (com.google.mlkit.vision.barcode.common.a) it2.next();
                int iM = aVar2.a.m();
                if (iM > 4096 || iM == 0) {
                    iM = -1;
                }
                G5 g5 = (G5) a.a.get(iM);
                if (g5 == null) {
                    g5 = G5.FORMAT_UNKNOWN;
                }
                c3268u.f(g5);
                H5 h5 = (H5) a.b.get(aVar2.a.f());
                if (h5 == null) {
                    h5 = H5.TYPE_UNKNOWN;
                }
                c3268u2.f(h5);
            }
        }
        long jElapsedRealtime = SystemClock.elapsedRealtime() - j2;
        C2824xF c2824xF = new C2824xF();
        c2824xF.b = this;
        c2824xF.a = jElapsedRealtime;
        c2824xF.c = enumC3290w5;
        c2824xF.d = c3268u;
        c2824xF.e = c3268u2;
        c2824xF.f = aVar;
        this.f.b(c2824xF, EnumC3298x5.ON_DEVICE_BARCODE_DETECT);
        com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = new com.quizlet.data.repository.studysetwithcreatorinclass.g(7);
        gVar.b = enumC3290w5;
        gVar.c = Boolean.valueOf(j);
        gVar.d = a.a(this.d);
        gVar.e = c3268u.h();
        gVar.f = c3268u2.h();
        com.google.mlkit.common.sdkinternal.k.a.execute(new RunnableC1782Ud(this.f, new W(gVar), jElapsedRealtime, new com.google.firebase.crashlytics.internal.settings.b(this, 1)));
        long jCurrentTimeMillis = System.currentTimeMillis();
        boolean z = this.i;
        long j3 = jCurrentTimeMillis - jElapsedRealtime;
        com.quizlet.data.interactor.school.b bVar = this.g;
        int i = true != z ? 24301 : 24302;
        int i2 = enumC3290w5.a;
        synchronized (bVar) {
            AtomicLong atomicLong = (AtomicLong) bVar.c;
            long jElapsedRealtime2 = SystemClock.elapsedRealtime();
            if (atomicLong.get() != -1 && jElapsedRealtime2 - ((AtomicLong) bVar.c).get() <= TimeUnit.MINUTES.toMillis(30L)) {
                return;
            }
            ((com.google.android.gms.common.internal.service.b) bVar.b).d(new TelemetryData(0, Arrays.asList(new MethodInvocation(i, i2, 0, j3, jCurrentTimeMillis, null, null, 0, -1)))).o(new l1(bVar, jElapsedRealtime2, 10));
        }
    }
}
