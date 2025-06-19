package androidx.appcompat.app;

import android.app.ActivityManager;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Parcel;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.view.accessibility.AccessibilityNodeInfo;
import androidx.appcompat.widget.C0122z;
import androidx.camera.core.C0194q;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.InterfaceC0159a0;
import androidx.camera.core.impl.X;
import androidx.compose.animation.AbstractC0228b;
import androidx.compose.animation.e0;
import androidx.compose.animation.f0;
import androidx.compose.animation.g0;
import androidx.compose.animation.p0;
import androidx.compose.foundation.lazy.layout.InterfaceC0440l;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.InterfaceC1062t;
import androidx.core.view.V;
import androidx.core.view.z0;
import assistantMode.refactored.modelTypes.Card;
import assistantMode.refactored.modelTypes.CardSide;
import com.bumptech.glide.load.resource.bitmap.DefaultImageHeaderParser$Reader$EndOfFileException;
import com.comscore.streaming.EventType;
import com.google.android.gms.auth.api.identity.SavePasswordRequest;
import com.google.android.gms.auth.api.signin.internal.SignInHubActivity;
import com.google.android.gms.internal.ads.InterfaceC1681De;
import com.google.android.gms.internal.ads.InterfaceC2529qe;
import com.google.android.gms.internal.ads.InterfaceC2843xs;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.measurement.internal.D0;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.measurement.internal.g1;
import com.skydoves.balloon.internals.DefinitionKt;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class Q implements InterfaceC0159a0, androidx.compose.animation.core.F, InterfaceC0440l, androidx.compose.foundation.gestures.snapping.m, InterfaceC1062t, com.bumptech.glide.util.pool.a, com.bumptech.glide.load.resource.bitmap.k, InterfaceC1681De, InterfaceC2843xs, androidx.loader.app.a, com.google.android.gms.common.api.internal.i, com.google.android.material.button.a, com.google.android.material.resources.a {
    public Object a;

    public /* synthetic */ Q(Object obj) {
        this.a = obj;
    }

    public static Q C(int i, int i2, int i3) {
        return new Q(AccessibilityNodeInfo.CollectionInfo.obtain(i, i2, false, i3));
    }

    /* JADX WARN: Code restructure failed: missing block: B:348:0x018e, code lost:
    
        r3 = 0;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:158:0x02d4  */
    /* JADX WARN: Removed duplicated region for block: B:171:0x0302  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x0306  */
    /* JADX WARN: Removed duplicated region for block: B:177:0x0314  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.ArrayList D(androidx.appcompat.app.Q r43, java.lang.String r44) {
        /*
            Method dump skipped, instructions count: 1868
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.Q.D(androidx.appcompat.app.Q, java.lang.String):java.util.ArrayList");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1681De
    public void A(String str, int i, String str2, boolean z) {
        InterfaceC2529qe interfaceC2529qe = ((com.google.android.gms.ads.internal.overlay.d) this.a).d;
        if (interfaceC2529qe != null) {
            interfaceC2529qe.e0();
        }
    }

    public assistantMode.refactored.modelTypes.b B(assistantMode.enums.m mVar) {
        Object next;
        Iterator it2 = ((Card) this.a).e.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (((CardSide) next).b == mVar) {
                break;
            }
        }
        CardSide cardSide = (CardSide) next;
        if (cardSide != null) {
            return new assistantMode.refactored.modelTypes.b(cardSide);
        }
        return null;
    }

    public void E() {
        g1 g1Var = (g1) this.a;
        g1Var.S();
        Y y = (Y) g1Var.b;
        com.google.android.gms.measurement.internal.O o = y.h;
        Y.h(o);
        com.google.android.gms.common.util.b bVar = y.n;
        bVar.getClass();
        if (o.b0(System.currentTimeMillis())) {
            com.google.android.gms.measurement.internal.O o2 = y.h;
            Y.h(o2);
            o2.n.a(true);
            ActivityManager.RunningAppProcessInfo runningAppProcessInfo = new ActivityManager.RunningAppProcessInfo();
            ActivityManager.getMyMemoryState(runningAppProcessInfo);
            if (runningAppProcessInfo.importance == 100) {
                com.google.android.gms.measurement.internal.I i = y.i;
                Y.k(i);
                i.o.f("Detected application was in foreground");
                bVar.getClass();
                G(System.currentTimeMillis());
            }
        }
    }

    public void F(long j) {
        g1 g1Var = (g1) this.a;
        g1Var.S();
        g1Var.V();
        Y y = (Y) g1Var.b;
        com.google.android.gms.measurement.internal.O o = y.h;
        Y.h(o);
        boolean zB0 = o.b0(j);
        com.google.android.gms.measurement.internal.O o2 = y.h;
        if (zB0) {
            Y.h(o2);
            o2.n.a(true);
            y.n().Z();
        }
        Y.h(o2);
        o2.r.b(j);
        if (o2.n.b()) {
            G(j);
        }
    }

    public void G(long j) {
        g1 g1Var = (g1) this.a;
        g1Var.S();
        Y y = (Y) g1Var.b;
        if (y.a()) {
            com.google.android.gms.measurement.internal.O o = y.h;
            Y.h(o);
            o.r.b(j);
            y.n.getClass();
            long jElapsedRealtime = SystemClock.elapsedRealtime();
            com.google.android.gms.measurement.internal.I i = y.i;
            Y.k(i);
            i.o.g("Session started, time", Long.valueOf(jElapsedRealtime));
            long j2 = j / 1000;
            Long lValueOf = Long.valueOf(j2);
            D0 d0 = y.p;
            Y.j(d0);
            d0.o0(j, lValueOf, "auto", "_sid");
            Y.h(o);
            o.s.b(j2);
            o.n.a(false);
            Bundle bundle = new Bundle();
            bundle.putLong("_sid", j2);
            Y.j(d0);
            d0.d0("auto", "_s", bundle, j);
            String strL = o.x.l();
            if (TextUtils.isEmpty(strL)) {
                return;
            }
            Bundle bundle2 = new Bundle();
            bundle2.putString("_ffr", strL);
            Y.j(d0);
            d0.d0("auto", "_ssr", bundle2, j);
        }
    }

    @Override // androidx.compose.animation.core.F
    public float a() {
        return DefinitionKt.NO_Float_VALUE;
    }

    @Override // com.google.android.gms.common.api.internal.i
    public void accept(Object obj, Object obj2) {
        com.google.android.gms.internal.p000authapi.a aVar = new com.google.android.gms.internal.p000authapi.a((com.google.android.gms.tasks.f) obj2, 0);
        com.google.android.gms.internal.p000authapi.l lVar = (com.google.android.gms.internal.p000authapi.l) ((com.google.android.gms.internal.p000authapi.k) obj).m();
        SavePasswordRequest savePasswordRequest = (SavePasswordRequest) this.a;
        Parcel parcelX = lVar.X();
        int i = com.google.android.gms.internal.p000authapi.h.a;
        parcelX.writeStrongBinder(aVar);
        com.google.android.gms.internal.p000authapi.h.c(parcelX, savePasswordRequest);
        lVar.f0(2, parcelX);
    }

    @Override // com.bumptech.glide.load.resource.bitmap.k
    public int b() {
        return (o() << 8) | o();
    }

    @Override // com.bumptech.glide.util.pool.a
    public Object c() {
        C0122z c0122z = (C0122z) this.a;
        return new com.bumptech.glide.load.engine.h((com.bumptech.glide.load.engine.k) c0122z.c, (com.quizlet.data.repository.course.membership.c) c0122z.d);
    }

    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0440l
    public int d() {
        return ((androidx.compose.foundation.lazy.A) this.a).h().m;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2843xs
    public void e(int i, long j) {
        ((com.google.android.gms.ads.internal.e) this.a).h.s(i, System.currentTimeMillis() - j);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2843xs
    public void f(int i, long j, String str) {
        ((com.google.android.gms.ads.internal.e) this.a).h.u(i, System.currentTimeMillis() - j, null, null, str);
    }

    @Override // androidx.loader.app.a
    public void g() {
    }

    @Override // androidx.compose.foundation.gestures.snapping.m
    public float h(float f, float f2) {
        return DefinitionKt.NO_Float_VALUE;
    }

    @Override // androidx.loader.app.a
    public /* bridge */ /* synthetic */ void i(Object obj) {
        SignInHubActivity signInHubActivity = (SignInHubActivity) this.a;
        signInHubActivity.setResult(signInHubActivity.e, signInHubActivity.f);
        signInHubActivity.finish();
    }

    @Override // androidx.compose.foundation.gestures.snapping.m
    public float j(float f) {
        return ((androidx.work.impl.model.c) this.a).j(f);
    }

    @Override // androidx.camera.core.impl.InterfaceC0159a0
    public void k(Object obj) {
        ((androidx.core.util.a) this.a).accept(obj);
    }

    @Override // com.google.android.material.resources.a
    public void l(Typeface typeface) {
        com.google.android.material.internal.b bVar = (com.google.android.material.internal.b) this.a;
        if (bVar.o(typeface)) {
            bVar.i(false);
        }
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0440l
    public int m() {
        androidx.compose.foundation.lazy.r rVar = (androidx.compose.foundation.lazy.r) CollectionsKt.V(((androidx.compose.foundation.lazy.A) this.a).h().j);
        if (rVar != null) {
            return rVar.a;
        }
        return 0;
    }

    @Override // androidx.compose.animation.core.F
    public float n(float f, float f2, long j) {
        long j2 = j / 1000000;
        e0 e0VarB = ((f0) this.a).b(f2);
        long j3 = e0VarB.c;
        return (Math.signum(e0VarB.a) * e0VarB.b * AbstractC0228b.a(j3 > 0 ? j2 / j3 : 1.0f).a) + f;
    }

    @Override // com.bumptech.glide.load.resource.bitmap.k
    public short o() throws DefaultImageHeaderParser$Reader$EndOfFileException {
        ByteBuffer byteBuffer = (ByteBuffer) this.a;
        if (byteBuffer.remaining() >= 1) {
            return (short) (byteBuffer.get() & 255);
        }
        throw new DefaultImageHeaderParser$Reader$EndOfFileException();
    }

    @Override // androidx.camera.core.impl.InterfaceC0159a0
    public void onError(Throwable th) {
        AbstractC3053s1.d("ObserverToConsumerAdapter", "Unexpected error in Observable", th);
    }

    @Override // androidx.loader.app.a
    public androidx.loader.content.c p() {
        Set set = com.google.android.gms.common.api.h.a;
        synchronized (set) {
        }
        return new com.google.android.gms.auth.api.signin.internal.c((SignInHubActivity) this.a, set);
    }

    @Override // androidx.compose.animation.core.F
    public long q(float f) {
        return ((long) (Math.exp(((f0) this.a).c(f) / (g0.a - 1.0d)) * 1000.0d)) * 1000000;
    }

    @Override // androidx.compose.animation.core.F
    public float r(float f, float f2) {
        double dC = ((f0) this.a).c(f2);
        double d = g0.a;
        return (Math.signum(f2) * ((float) (Math.exp((d / (d - 1.0d)) * dC) * r0.b * r0.c))) + f;
    }

    @Override // com.bumptech.glide.load.resource.bitmap.k
    public int s(int i, byte[] bArr) {
        ByteBuffer byteBuffer = (ByteBuffer) this.a;
        int iMin = Math.min(i, byteBuffer.remaining());
        if (iMin == 0) {
            return -1;
        }
        byteBuffer.get(bArr, 0, iMin);
        return iMin;
    }

    @Override // com.bumptech.glide.load.resource.bitmap.k
    public long skip(long j) {
        ByteBuffer byteBuffer = (ByteBuffer) this.a;
        int iMin = (int) Math.min(byteBuffer.remaining(), j);
        byteBuffer.position(byteBuffer.position() + iMin);
        return iMin;
    }

    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0440l
    public void t(int i, int i2) {
        ((androidx.compose.foundation.lazy.A) this.a).k(i, i2);
    }

    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0440l
    public int u() {
        return ((androidx.compose.foundation.lazy.A) this.a).d.b();
    }

    @Override // androidx.compose.animation.core.F
    public float v(long j, float f) {
        long j2 = j / 1000000;
        e0 e0VarB = ((f0) this.a).b(f);
        long j3 = e0VarB.c;
        return (((Math.signum(e0VarB.a) * AbstractC0228b.a(j3 > 0 ? j2 / j3 : 1.0f).b) * e0VarB.b) / j3) * 1000.0f;
    }

    @Override // androidx.core.view.InterfaceC1062t
    public androidx.core.view.D0 w(androidx.core.view.D0 d0, View view) {
        CoordinatorLayout coordinatorLayout = (CoordinatorLayout) this.a;
        if (!Objects.equals(coordinatorLayout.n, d0)) {
            coordinatorLayout.n = d0;
            boolean z = d0.d() > 0;
            coordinatorLayout.o = z;
            coordinatorLayout.setWillNotDraw(!z && coordinatorLayout.getBackground() == null);
            z0 z0Var = d0.a;
            if (!z0Var.o()) {
                int childCount = coordinatorLayout.getChildCount();
                for (int i = 0; i < childCount; i++) {
                    View childAt = coordinatorLayout.getChildAt(i);
                    WeakHashMap weakHashMap = V.a;
                    if (childAt.getFitsSystemWindows() && ((androidx.coordinatorlayout.widget.e) childAt.getLayoutParams()).a != null && z0Var.o()) {
                        break;
                    }
                }
            }
            coordinatorLayout.requestLayout();
        }
        return d0;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r1v2, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0440l
    public float x(int i) {
        Object obj;
        androidx.compose.foundation.lazy.q qVarH = ((androidx.compose.foundation.lazy.A) this.a).h();
        if (qVarH.j.isEmpty()) {
            return DefinitionKt.NO_Float_VALUE;
        }
        ?? r1 = qVarH.j;
        int size = r1.size();
        int i2 = 0;
        while (true) {
            if (i2 >= size) {
                obj = null;
                break;
            }
            obj = r1.get(i2);
            if (((androidx.compose.foundation.lazy.r) obj).a == i) {
                break;
            }
            i2++;
        }
        if (((androidx.compose.foundation.lazy.r) obj) != null) {
            return r5.o;
        }
        int size2 = r1.size();
        int i3 = 0;
        for (int i4 = 0; i4 < size2; i4++) {
            i3 += ((androidx.compose.foundation.lazy.r) r1.get(i4)).p;
        }
        return ((i - y()) * ((i3 / r1.size()) + qVarH.p)) - u();
    }

    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0440l
    public int y() {
        return ((androidx.compose.foundation.lazy.A) this.a).d.a();
    }

    public void z(androidx.room.migration.a... migrations) {
        Intrinsics.checkNotNullParameter(migrations, "migrations");
        for (androidx.room.migration.a aVar : migrations) {
            int i = aVar.a;
            LinkedHashMap linkedHashMap = (LinkedHashMap) this.a;
            Integer numValueOf = Integer.valueOf(i);
            Object treeMap = linkedHashMap.get(numValueOf);
            if (treeMap == null) {
                treeMap = new TreeMap();
                linkedHashMap.put(numValueOf, treeMap);
            }
            TreeMap treeMap2 = (TreeMap) treeMap;
            int i2 = aVar.b;
            if (treeMap2.containsKey(Integer.valueOf(i2))) {
                Log.w("ROOM", "Overriding migration " + treeMap2.get(Integer.valueOf(i2)) + " with " + aVar);
            }
            treeMap2.put(Integer.valueOf(i2), aVar);
        }
    }

    public Q(androidx.compose.ui.unit.b bVar) {
        this.a = new f0(p0.a, bVar);
    }

    public Q(int i) {
        Object objE;
        switch (i) {
            case 11:
                this.a = new AtomicInteger(0);
                return;
            case 13:
                this.a = new LinkedHashMap();
                return;
            case 19:
                this.a = new ConcurrentHashMap();
                return;
            case EventType.CDN /* 26 */:
                this.a = new com.google.android.gms.tasks.m();
                return;
            default:
                X xB = X.b();
                this.a = xB;
                Object objE2 = null;
                try {
                    objE = xB.e(androidx.camera.core.internal.k.A0);
                } catch (IllegalArgumentException unused) {
                    objE = null;
                }
                Class cls = (Class) objE;
                if (cls != null && !cls.equals(C0194q.class)) {
                    throw new IllegalArgumentException("Invalid target class configuration for " + this + ": " + cls);
                }
                C0162c c0162c = androidx.camera.core.internal.k.A0;
                X x = (X) this.a;
                x.m(c0162c, C0194q.class);
                try {
                    objE2 = x.e(androidx.camera.core.internal.k.z0);
                } catch (IllegalArgumentException unused2) {
                }
                if (objE2 == null) {
                    x.m(androidx.camera.core.internal.k.z0, C0194q.class.getCanonicalName() + "-" + UUID.randomUUID());
                    return;
                }
                return;
        }
    }

    public Q(ByteBuffer byteBuffer) {
        this.a = byteBuffer;
        byteBuffer.order(ByteOrder.BIG_ENDIAN);
    }
}
