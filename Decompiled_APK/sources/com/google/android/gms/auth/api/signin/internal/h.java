package com.google.android.gms.auth.api.signin.internal;

import android.content.ClipData;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcel;
import android.text.TextUtils;
import android.util.Pair;
import android.view.ContentInfo;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import androidx.appcompat.app.B;
import androidx.appcompat.view.menu.F;
import androidx.appcompat.view.menu.y;
import androidx.appcompat.widget.C0095l;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.V;
import androidx.camera.camera2.internal.compat.quirk.ExtraCroppingQuirk;
import androidx.camera.camera2.internal.p0;
import androidx.camera.core.L;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.N;
import androidx.camera.core.impl.W;
import androidx.camera.core.impl.X;
import androidx.camera.core.impl.z0;
import androidx.collection.C0226y;
import androidx.compose.animation.core.InterfaceC0269u;
import androidx.compose.foundation.lazy.layout.InterfaceC0440l;
import androidx.compose.foundation.pager.C0472k;
import androidx.compose.foundation.pager.E;
import androidx.compose.foundation.pager.x;
import androidx.compose.runtime.F0;
import androidx.compose.runtime.H0;
import androidx.compose.runtime.L0;
import androidx.core.view.AbstractC1042d;
import androidx.core.view.C1050h;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1044e;
import androidx.core.view.InterfaceC1062t;
import androidx.core.view.accessibility.n;
import androidx.viewpager2.widget.ViewPager2;
import com.android.billingclient.api.s;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.common.moduleinstall.internal.ApiFeatureRequest;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.Kk;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.material.appbar.CollapsingToolbarLayout;
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.WeakHashMap;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.collections.C4930v;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class h implements y, androidx.camera.core.impl.utils.futures.c, z0, androidx.camera.core.impl.utils.futures.a, InterfaceC0269u, InterfaceC0440l, InterfaceC1044e, n, coil3.memory.f, com.bumptech.glide.load.data.g, Pv, com.google.android.gms.common.api.internal.i, OnCompleteListener, InterfaceC1062t, com.google.android.material.floatingactionbutton.g {
    public static h c;
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ h(com.google.android.gms.common.moduleinstall.internal.d dVar, ApiFeatureRequest apiFeatureRequest) {
        this.a = 23;
        this.b = apiFeatureRequest;
    }

    public static synchronized h B(Context context) {
        h hVar;
        Context applicationContext = context.getApplicationContext();
        synchronized (h.class) {
            hVar = c;
            if (hVar == null) {
                hVar = new h(applicationContext);
                c = hVar;
            }
        }
        return hVar;
        return hVar;
    }

    public JSONObject A() {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("v", 1);
        JSONObject jSONObject2 = new JSONObject();
        jSONObject2.put("t", System.currentTimeMillis());
        jSONObject2.put("id", UUID.randomUUID().toString());
        com.amazon.aps.shared.metrics.model.e eVar = ((com.amazon.aps.shared.metrics.model.d) this.b).a;
        if (eVar.b()) {
            com.amazon.aps.shared.metrics.model.c cVar = com.amazon.aps.shared.a.a;
            JSONObject jSONObject3 = new JSONObject();
            jSONObject3.put("os", cVar.f);
            jSONObject3.put("dp", cVar.g);
            jSONObject3.put("ov", String.valueOf(Build.VERSION.SDK_INT));
            jSONObject3.put("dm", Build.MANUFACTURER);
            jSONObject3.put("md", Build.MODEL);
            String str = cVar.e;
            if (str != null) {
                jSONObject3.put("pcv", str);
            }
            String str2 = cVar.a;
            if (str2 != null) {
                jSONObject3.put("pc", str2);
            }
            String str3 = cVar.b;
            if (str3 != null) {
                jSONObject3.put("ds", str3);
            }
            String str4 = cVar.c;
            if (str4 != null) {
                jSONObject3.put("dt", str4);
            }
            String str5 = cVar.d;
            if (str5 != null) {
                jSONObject3.put("ct", str5);
            }
            jSONObject2.put("di", jSONObject3);
            com.amazon.aps.shared.metrics.model.n nVar = com.amazon.aps.shared.a.b;
            JSONObject jSONObject4 = new JSONObject();
            String str6 = nVar.a;
            if (str6 != null) {
                jSONObject4.put("cv", str6);
            }
            jSONObject2.put("s", jSONObject4);
        }
        JSONArray jSONArray = new JSONArray();
        JSONObject jSONObject5 = new JSONObject();
        jSONObject5.put(eVar.a(), eVar.c());
        jSONArray.put(jSONObject5);
        jSONObject.put("aps", jSONObject2.put("m", jSONArray));
        return jSONObject;
    }

    public synchronized void C() {
        a aVar = (a) this.b;
        ReentrantLock reentrantLock = aVar.a;
        reentrantLock.lock();
        try {
            aVar.b.edit().clear().apply();
        } finally {
            reentrantLock.unlock();
        }
    }

    @Override // coil3.memory.f
    public long a() {
        return 0L;
    }

    @Override // com.google.android.gms.common.api.internal.i
    public void accept(Object obj, Object obj2) {
        com.google.android.gms.common.moduleinstall.internal.c cVar = new com.google.android.gms.common.moduleinstall.internal.c((com.google.android.gms.tasks.f) obj2, 1);
        com.google.android.gms.common.moduleinstall.internal.b bVar = (com.google.android.gms.common.moduleinstall.internal.b) ((com.google.android.gms.common.moduleinstall.internal.e) obj).m();
        ApiFeatureRequest apiFeatureRequest = (ApiFeatureRequest) this.b;
        Parcel parcelObtain = Parcel.obtain();
        parcelObtain.writeInterfaceToken(bVar.c);
        com.google.android.gms.internal.base.a.c(parcelObtain, cVar);
        com.google.android.gms.internal.base.a.b(parcelObtain, apiFeatureRequest);
        parcelObtain.writeStrongBinder(null);
        bVar.V(2, parcelObtain);
    }

    @Override // androidx.camera.core.impl.utils.futures.a, com.google.android.datatransport.runtime.scheduling.persistence.e, io.reactivex.rxjava3.functions.h
    public com.google.common.util.concurrent.e apply(Object obj) {
        return androidx.camera.core.impl.utils.futures.i.c(((androidx.arch.core.util.a) this.b).mo0apply(obj));
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int b() {
        return ((ExtendedFloatingActionButton) this.b).getCollapsedSize();
    }

    @Override // androidx.core.view.InterfaceC1044e
    public C1050h build() {
        return new C1050h(new com.google.android.gms.internal.instantapps.a(((ContentInfo.Builder) this.b).build()));
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        com.google.android.gms.ads.internal.util.client.i.d("Initialized webview successfully for SDKCore.");
        if (((Boolean) r.d.c.a(AbstractC2773w7.J9)).booleanValue()) {
            com.google.android.gms.ads.nonagon.signalgeneration.i iVar = (com.google.android.gms.ads.nonagon.signalgeneration.i) this.b;
            AbstractC3429b3.f(iVar.l, "sgs", new Pair("se", "query_g"), new Pair("ad_format", "BANNER"), new Pair("rtype", Integer.toString(6)), new Pair("scar", "true"), new Pair("sgi_rn", Integer.toString(iVar.D.get())));
            iVar.C.set(true);
        }
    }

    @Override // coil3.memory.f
    public void clear() {
    }

    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0440l
    public int d() {
        return ((E) this.b).l();
    }

    @Override // androidx.appcompat.view.menu.y
    public void e(androidx.appcompat.view.menu.n nVar, boolean z) {
        switch (this.a) {
            case 1:
                ((B) this.b).q(nVar);
                break;
            default:
                if (nVar instanceof F) {
                    ((F) nVar).z.k().c(false);
                }
                y yVar = ((C0095l) this.b).e;
                if (yVar != null) {
                    yVar.e(nVar, z);
                    break;
                }
                break;
        }
    }

    @Override // com.bumptech.glide.load.data.g
    public void f() {
    }

    @Override // androidx.core.view.accessibility.n
    public boolean g(View view) {
        int currentItem = ((ViewPager2) view).getCurrentItem() + 1;
        ViewPager2 viewPager2 = (ViewPager2) ((androidx.work.impl.model.n) this.b).d;
        if (viewPager2.r) {
            viewPager2.c(currentItem);
        }
        return true;
    }

    @Override // androidx.compose.animation.core.InterfaceC0269u
    public androidx.compose.animation.core.E get(int i) {
        return (androidx.compose.animation.core.E) this.b;
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public ViewGroup.LayoutParams getLayoutParams() {
        ExtendedFloatingActionButton extendedFloatingActionButton = (ExtendedFloatingActionButton) this.b;
        return new ViewGroup.LayoutParams(extendedFloatingActionButton.getCollapsedSize(), extendedFloatingActionButton.getCollapsedSize());
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int getWidth() {
        return ((ExtendedFloatingActionButton) this.b).getCollapsedSize();
    }

    @Override // coil3.memory.f
    public boolean h(coil3.memory.a aVar) {
        return false;
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int i() {
        return ((ExtendedFloatingActionButton) this.b).getCollapsedPadding();
    }

    @Override // androidx.core.view.InterfaceC1044e
    public void j(Bundle bundle) {
        ((ContentInfo.Builder) this.b).setExtras(bundle);
    }

    @Override // coil3.memory.f
    public void k(coil3.memory.a aVar, coil3.j jVar, Map map, long j) {
        ((s) this.b).m(aVar, jVar, map, j);
    }

    @Override // com.bumptech.glide.load.data.g
    public Object l() {
        ByteBuffer byteBuffer = (ByteBuffer) this.b;
        byteBuffer.position(0);
        return byteBuffer;
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0440l
    public int m() {
        return ((C0472k) CollectionsKt.U(((E) this.b).k().a)).a;
    }

    @Override // androidx.core.view.InterfaceC1044e
    public void n(Uri uri) {
        ((ContentInfo.Builder) this.b).setLinkUri(uri);
    }

    @Override // coil3.memory.f
    public coil3.memory.b o(coil3.memory.a aVar) {
        return null;
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x00df, code lost:
    
        if (r0.isEmpty() == false) goto L24;
     */
    @Override // com.google.android.gms.tasks.OnCompleteListener
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onComplete(com.google.android.gms.tasks.Task r8) {
        /*
            Method dump skipped, instructions count: 278
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.auth.api.signin.internal.h.onComplete(com.google.android.gms.tasks.Task):void");
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
        synchronized (((V) this.b).a) {
            try {
                ((V) this.b).d.q();
                int iK = AbstractC0147y.k(((V) this.b).i);
                if ((iK == 3 || iK == 5 || iK == 6) && !(th instanceof CancellationException)) {
                    AbstractC3053s1.i("CaptureSession", "Opening session with fail ".concat(AbstractC0147y.m(((V) this.b).i)), th);
                    ((V) this.b).d();
                }
            } finally {
            }
        }
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public /* bridge */ /* synthetic */ void onSuccess(Object obj) {
    }

    @Override // coil3.memory.f
    public void p(long j) {
    }

    @Override // androidx.camera.core.InterfaceC0197u
    public W q() {
        return (X) this.b;
    }

    @Override // androidx.core.view.InterfaceC1044e
    public void r(int i) {
        ((ContentInfo.Builder) this.b).setFlags(i);
    }

    @Override // androidx.camera.core.impl.z0
    public A0 s() {
        return new N(C0163c0.a((X) this.b));
    }

    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0440l
    public void t(int i, int i2) {
        E e = (E) this.b;
        p0 p0Var = e.c;
        ((H0) p0Var.d).j(i);
        ((androidx.compose.foundation.lazy.layout.X) p0Var.f).a(i);
        ((F0) p0Var.a).j(i2 / e.n());
        p0Var.e = null;
        androidx.compose.ui.node.E e2 = (androidx.compose.ui.node.E) ((L0) e.x).getValue();
        if (e2 != null) {
            e2.k();
        }
    }

    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0440l
    public int u() {
        return ((E) this.b).e;
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int v() {
        return ((ExtendedFloatingActionButton) this.b).getCollapsedPadding();
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) {
        CollapsingToolbarLayout collapsingToolbarLayout = (CollapsingToolbarLayout) this.b;
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        D0 d02 = collapsingToolbarLayout.getFitsSystemWindows() ? d0 : null;
        if (!Objects.equals(collapsingToolbarLayout.A, d02)) {
            collapsingToolbarLayout.A = d02;
            collapsingToolbarLayout.requestLayout();
        }
        return d0.a.c();
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0440l
    public float x(int i) {
        Object obj;
        E e = (E) this.b;
        ?? r1 = e.k().a;
        int size = r1.size();
        int i2 = 0;
        while (true) {
            if (i2 >= size) {
                obj = null;
                break;
            }
            obj = r1.get(i2);
            if (((C0472k) obj).a == i) {
                break;
            }
            i2++;
        }
        if (((C0472k) obj) != null) {
            return r4.l;
        }
        return ((i - e.j()) * (((x) ((L0) e.o).getValue()).c + e.m())) - (e.c.j() * e.n());
    }

    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0440l
    public int y() {
        return ((E) this.b).d;
    }

    @Override // androidx.appcompat.view.menu.y
    public boolean z(androidx.appcompat.view.menu.n nVar) {
        switch (this.a) {
            case 1:
                Window.Callback callback = ((B) this.b).l.getCallback();
                if (callback == null) {
                    return true;
                }
                callback.onMenuOpened(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY, nVar);
                return true;
            default:
                C0095l c0095l = (C0095l) this.b;
                if (nVar == c0095l.c) {
                    return false;
                }
                ((F) nVar).A.getClass();
                c0095l.getClass();
                y yVar = c0095l.e;
                if (yVar != null) {
                    return yVar.z(nVar);
                }
                return false;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        com.google.android.gms.ads.internal.j.C.h.h("SignalGeneratorImpl.initializeWebViewForSignalCollection", th);
        com.google.android.gms.ads.nonagon.signalgeneration.i iVar = (com.google.android.gms.ads.nonagon.signalgeneration.i) this.b;
        Kk kk = iVar.l;
        Pair pair = new Pair("sgf_reason", th.getMessage());
        Pair pair2 = new Pair("se", "query_g");
        Pair pair3 = new Pair("ad_format", "BANNER");
        Pair pair4 = new Pair("rtype", Integer.toString(6));
        Pair pair5 = new Pair("scar", "true");
        AtomicInteger atomicInteger = iVar.D;
        AbstractC3429b3.f(kk, "sgf", pair, pair2, pair3, pair4, pair5, new Pair("sgi_rn", Integer.toString(atomicInteger.get())));
        com.google.android.gms.ads.internal.util.client.i.f("Failed to initialize webview for loading SDKCore. ", th);
        C2601s7 c2601s7 = AbstractC2773w7.J9;
        r rVar = r.d;
        if (!((Boolean) rVar.c.a(c2601s7)).booleanValue() || iVar.C.get()) {
            return;
        }
        if (atomicInteger.getAndIncrement() < ((Integer) rVar.c.a(AbstractC2773w7.K9)).intValue()) {
            iVar.g4();
        }
    }

    public /* synthetic */ h(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public h(Context context) {
        String strE;
        this.a = 0;
        a aVarA = a.a(context);
        this.b = aVarA;
        aVarA.b();
        String strE2 = aVarA.e("defaultGoogleSignInAccount");
        if (TextUtils.isEmpty(strE2) || (strE = aVarA.e(a.f("googleSignInOptions", strE2))) == null) {
            return;
        }
        try {
            GoogleSignInOptions.a(strE);
        } catch (JSONException unused) {
        }
    }

    public h(com.amazon.aps.shared.metrics.model.d metrics) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(metrics, "metrics");
        this.b = metrics;
    }

    public h(boolean z) {
        this.a = 14;
        this.b = new AtomicBoolean(z);
    }

    public h(androidx.compose.runtime.saveable.c cVar) {
        this.a = 15;
        this.b = new WeakReference(cVar);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public h(int i) {
        this(X.b());
        this.a = i;
        switch (i) {
            case 6:
                break;
            case 11:
                this.b = new androidx.compose.ui.text.caches.b(8);
                break;
            case 29:
                break;
            default:
                this.b = (ExtraCroppingQuirk) androidx.camera.camera2.internal.compat.quirk.b.a.b(ExtraCroppingQuirk.class);
                break;
        }
    }

    public h(long[] jArr) {
        C0226y c0226y;
        int i;
        this.a = 10;
        if (jArr != null) {
            long[] elements = Arrays.copyOf(jArr, jArr.length);
            c0226y = new C0226y(elements.length);
            int i2 = c0226y.b;
            Intrinsics.checkNotNullParameter(elements, "elements");
            if (i2 >= 0 && i2 <= (i = c0226y.b)) {
                if (elements.length != 0) {
                    int length = i + elements.length;
                    long[] jArr2 = c0226y.a;
                    if (jArr2.length < length) {
                        long[] jArrCopyOf = Arrays.copyOf(jArr2, Math.max(length, (jArr2.length * 3) / 2));
                        Intrinsics.checkNotNullExpressionValue(jArrCopyOf, "copyOf(...)");
                        c0226y.a = jArrCopyOf;
                    }
                    long[] jArr3 = c0226y.a;
                    int i3 = c0226y.b;
                    if (i2 != i3) {
                        C4930v.g(jArr3, jArr3, elements.length + i2, i2, i3);
                    }
                    C4930v.g(elements, jArr3, i2, 0, elements.length);
                    c0226y.b += elements.length;
                }
            } else {
                androidx.collection.internal.a.d("");
                throw null;
            }
        } else {
            c0226y = new C0226y(16);
        }
        this.b = c0226y;
    }

    public h(ClipData clipData, int i) {
        this.a = 12;
        this.b = AbstractC1042d.p(clipData, i);
    }

    public h(X x) {
        Object objE;
        this.a = 6;
        this.b = x;
        Object objE2 = null;
        try {
            objE = x.e(androidx.camera.core.internal.k.A0);
        } catch (IllegalArgumentException unused) {
            objE = null;
        }
        Class cls = (Class) objE;
        if (cls != null && !cls.equals(L.class)) {
            throw new IllegalArgumentException("Invalid target class configuration for " + this + ": " + cls);
        }
        ((X) this.b).m(A0.v0, C0.a);
        C0162c c0162c = androidx.camera.core.internal.k.A0;
        X x2 = (X) this.b;
        x2.m(c0162c, L.class);
        try {
            objE2 = x2.e(androidx.camera.core.internal.k.z0);
        } catch (IllegalArgumentException unused2) {
        }
        if (objE2 == null) {
            ((X) this.b).m(androidx.camera.core.internal.k.z0, L.class.getCanonicalName() + "-" + UUID.randomUUID());
        }
    }
}
