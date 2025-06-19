package com.google.firebase.platforminfo;

import android.content.Context;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.params.DynamicRangeProfiles;
import android.os.Build;
import androidx.activity.t;
import androidx.appcompat.app.L;
import androidx.appcompat.app.Q;
import androidx.appcompat.widget.InterfaceC0071a0;
import androidx.appcompat.widget.u1;
import androidx.camera.camera2.internal.C0143u;
import androidx.camera.camera2.internal.compat.k;
import androidx.camera.camera2.internal.compat.params.d;
import androidx.camera.core.InterfaceC0197u;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.H;
import androidx.camera.core.impl.W;
import androidx.camera.core.impl.X;
import androidx.camera.core.impl.utils.futures.l;
import androidx.camera.core.processing.f;
import androidx.compose.animation.d0;
import androidx.compose.foundation.gestures.C0327h;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.graphics.K;
import androidx.compose.ui.graphics.N;
import androidx.compose.ui.graphics.V;
import androidx.compose.ui.text.C0981a;
import androidx.concurrent.futures.i;
import androidx.concurrent.futures.j;
import androidx.paging.C1336q0;
import androidx.paging.i1;
import androidx.paging.k1;
import com.bumptech.glide.load.model.o;
import com.comscore.streaming.EventType;
import com.google.android.datatransport.runtime.backends.e;
import com.google.android.datatransport.runtime.backends.g;
import com.google.android.datatransport.runtime.m;
import com.google.android.datatransport.runtime.r;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.measurement.internal.F0;
import com.google.gson.internal.n;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.ranges.IntRange;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.InterfaceC5026k;

/* loaded from: classes2.dex */
public class c implements u1, InterfaceC0071a0, InterfaceC0197u, androidx.camera.core.impl.utils.futures.c, j, V, F0, n {
    public static volatile c b;
    public Object a;

    public /* synthetic */ c(Object obj) {
        this.a = obj;
    }

    public static c l(H h) {
        c cVar = new c(5);
        h.h(new C0143u(2, cVar, h));
        return cVar;
    }

    public static c m(k kVar) {
        DynamicRangeProfiles dynamicRangeProfilesJ;
        int i = Build.VERSION.SDK_INT;
        c cVar = null;
        if (i >= 33 && (dynamicRangeProfilesJ = t.j(kVar.a(CameraCharacteristics.REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES))) != null) {
            AbstractC3242q6.h("DynamicRangeProfiles can only be converted to DynamicRangesCompat on API 33 or higher.", i >= 33);
            cVar = new c(new androidx.camera.camera2.internal.compat.params.c(dynamicRangeProfilesJ));
        }
        return cVar == null ? d.a : cVar;
    }

    @Override // com.google.gson.internal.n
    public Object E() {
        Constructor constructor = (Constructor) this.a;
        try {
            return constructor.newInstance(null);
        } catch (IllegalAccessException e) {
            throw new AssertionError(e);
        } catch (InstantiationException e2) {
            throw new RuntimeException("Failed to invoke " + constructor + " with no args", e2);
        } catch (InvocationTargetException e3) {
            throw new RuntimeException("Failed to invoke " + constructor + " with no args", e3.getTargetException());
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0027  */
    @Override // com.google.android.gms.measurement.internal.F0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void a(int r18, java.io.IOException r19, byte[] r20) {
        /*
            Method dump skipped, instructions count: 352
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.platforminfo.c.a(int, java.io.IOException, byte[]):void");
    }

    public void b(int i) {
    }

    public void c(int i) {
    }

    @Override // androidx.concurrent.futures.j
    public Object d(i iVar) {
        l lVar = (l) this.a;
        AbstractC3242q6.h("The result can only set once!", lVar.f == null);
        lVar.f = iVar;
        return "ListFuture[" + this + "]";
    }

    @Override // androidx.compose.ui.graphics.V
    public N e(long j, androidx.compose.ui.unit.k kVar, androidx.compose.ui.unit.b bVar) {
        return new K((C0850j) this.a);
    }

    public void f(int i, float f) {
    }

    public void g(k1 viewportHint) {
        Intrinsics.checkNotNullParameter(viewportHint, "viewportHint");
        C1336q0 c1336q0 = (C1336q0) this.a;
        Intrinsics.checkNotNullParameter(viewportHint, "viewportHint");
        com.google.android.gms.internal.instantapps.a aVar = c1336q0.e;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(viewportHint, "viewportHint");
        ((com.quizlet.data.repository.studysetwithcreator.d) aVar.b).c(viewportHint instanceof i1 ? (i1) viewportHint : null, new C0981a(viewportHint, 4));
    }

    public L h() {
        return new L(C0163c0.a((X) this.a), 4);
    }

    public com.google.android.datatransport.runtime.j i() {
        Context context = (Context) this.a;
        if (context == null) {
            throw new IllegalStateException(Context.class.getCanonicalName() + " must be set");
        }
        com.google.android.datatransport.runtime.j jVar = new com.google.android.datatransport.runtime.j();
        jVar.a = com.google.android.datatransport.runtime.dagger.internal.a.a(com.google.android.datatransport.runtime.l.a);
        e eVar = new e(context, 3);
        jVar.b = eVar;
        jVar.c = com.google.android.datatransport.runtime.dagger.internal.a.a(new g(eVar, new e(eVar, 0), 0));
        e eVar2 = jVar.b;
        jVar.d = new e(eVar2, 2);
        javax.inject.a aVarA = com.google.android.datatransport.runtime.dagger.internal.a.a(new g(jVar.d, com.google.android.datatransport.runtime.dagger.internal.a.a(new e(eVar2, 1)), 1));
        jVar.e = aVarA;
        m mVar = new m(1);
        e eVar3 = jVar.b;
        r rVar = new r(eVar3, aVarA, mVar, 1);
        javax.inject.a aVar = jVar.a;
        javax.inject.a aVar2 = jVar.c;
        jVar.f = com.google.android.datatransport.runtime.dagger.internal.a.a(new r(new com.google.android.datatransport.runtime.scheduling.b(aVar, aVar2, rVar, aVarA, aVarA), new com.google.android.datatransport.runtime.scheduling.jobscheduling.j(eVar3, aVar2, aVarA, rVar, aVar, aVarA, aVarA), new com.google.android.datatransport.runtime.scheduling.jobscheduling.l(aVar, aVarA, rVar, aVarA), 0));
        return jVar;
    }

    public void j() {
        ((com.google.android.gms.tasks.m) ((Q) this.a).a).q(null);
    }

    public void k(CancellationException cancellationException) {
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.a;
        int i = bVar.c;
        InterfaceC5026k[] interfaceC5026kArr = new InterfaceC5026k[i];
        for (int i2 = 0; i2 < i; i2++) {
            interfaceC5026kArr[i2] = ((C0327h) bVar.a[i2]).b;
        }
        for (int i3 = 0; i3 < i; i3++) {
            interfaceC5026kArr[i3].b(cancellationException);
        }
        if (!bVar.l()) {
            throw new IllegalStateException("uncancelled requests present");
        }
    }

    public void n() {
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.a;
        int i = 0;
        int i2 = new IntRange(0, bVar.c - 1, 1).b;
        if (i2 >= 0) {
            while (true) {
                C5028l c5028l = ((C0327h) bVar.a[i]).b;
                Unit unit = Unit.a;
                p pVar = kotlin.r.b;
                c5028l.resumeWith(unit);
                if (i == i2) {
                    break;
                } else {
                    i++;
                }
            }
        }
        bVar.i();
    }

    public void o(String str) {
        String lowerCase = "Cache-Control".toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        ((LinkedHashMap) this.a).put(lowerCase, B.k(str));
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((f) this.a).run();
    }

    public void p() throws IOException {
        ArrayDeque arrayDeque = (ArrayDeque) this.a;
        if (arrayDeque.isEmpty()) {
            return;
        }
        throw new IOException("data item not completed, stackSize: " + arrayDeque.size() + " scope: " + t());
    }

    @Override // androidx.camera.core.InterfaceC0197u
    public W q() {
        throw null;
    }

    public void r(long j) throws IOException {
        long jT = t();
        if (jT != j) {
            if (jT != -1) {
                if (jT != -2) {
                    return;
                } else {
                    jT = -2;
                }
            }
            StringBuilder sbT = d0.t(j, "expected non-string scope or scope ", " but found ");
            sbT.append(jT);
            throw new IOException(sbT.toString());
        }
    }

    public long t() {
        ArrayDeque arrayDeque = (ArrayDeque) this.a;
        if (arrayDeque.isEmpty()) {
            return 0L;
        }
        return ((Long) arrayDeque.peek()).longValue();
    }

    public c(int i) {
        switch (i) {
            case 3:
                this.a = new Object();
                break;
            case 5:
                this.a = X.b();
                break;
            case 8:
                this.a = new androidx.compose.runtime.collection.b(new C0327h[16]);
                break;
            case 18:
                this.a = new o(1, 500L);
                break;
            case 20:
                this.a = new ConcurrentHashMap();
                new AtomicInteger(0);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                this.a = new ArrayDeque(16);
                break;
            case EventType.VIDEO /* 24 */:
                this.a = new Q(26);
                break;
            default:
                this.a = new HashSet();
                break;
        }
    }
}
