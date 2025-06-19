package com.google.android.gms.internal.instantapps;

import android.content.ClipData;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.TotalCaptureResult;
import android.os.Build;
import android.os.Parcel;
import android.view.ContentInfo;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.ListAdapter;
import android.widget.ListView;
import androidx.appcompat.app.A;
import androidx.appcompat.app.B;
import androidx.appcompat.app.L;
import androidx.appcompat.view.menu.l;
import androidx.appcompat.view.menu.y;
import androidx.appcompat.widget.ActionMenuView;
import androidx.appcompat.widget.InterfaceC0101o;
import androidx.appcompat.widget.M;
import androidx.appcompat.widget.Toolbar;
import androidx.appcompat.widget.u1;
import androidx.camera.camera2.internal.compat.k;
import androidx.camera.camera2.internal.o0;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.C0165d0;
import androidx.camera.core.impl.P;
import androidx.camera.core.impl.W;
import androidx.camera.core.impl.X;
import androidx.camera.core.impl.utils.futures.c;
import androidx.camera.core.impl.z0;
import androidx.compose.animation.core.AbstractC0267t;
import androidx.compose.animation.core.InterfaceC0269u;
import androidx.compose.animation.core.O0;
import androidx.compose.animation.core.Q0;
import androidx.core.view.AbstractC1042d;
import androidx.core.view.InterfaceC1048g;
import androidx.core.view.InterfaceC1053j;
import androidx.core.view.accessibility.n;
import androidx.core.widget.NestedScrollView;
import androidx.paging.C1352z;
import androidx.viewpager2.widget.ViewPager2;
import androidx.work.impl.WorkDatabase;
import androidx.work.impl.model.v;
import coil3.f;
import coil3.request.g;
import coil3.request.h;
import coil3.request.m;
import coil3.u;
import com.airbnb.lottie.network.d;
import com.google.android.gms.ads.nonagon.signalgeneration.q;
import com.google.android.gms.common.api.internal.i;
import com.google.android.gms.common.moduleinstall.internal.ApiFeatureRequest;
import com.google.android.gms.common.moduleinstall.internal.b;
import com.google.android.gms.common.moduleinstall.internal.e;
import com.google.android.gms.internal.ads.C1719Ka;
import com.google.android.gms.internal.ads.C1756Qb;
import com.google.android.gms.internal.ads.C2313ld;
import com.google.android.gms.internal.ads.C2661ti;
import com.google.android.gms.internal.ads.C2881yn;
import com.google.android.gms.internal.ads.D3;
import com.google.android.gms.internal.ads.Ew;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.ads.zzaqd;
import com.google.android.gms.internal.fido.AbstractC2937a;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.T;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.oss.licenses.OssLicensesMenuActivity;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.android.material.behavior.SwipeDismissBehavior;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.FileNotFoundException;
import java.util.ArrayDeque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.WeakHashMap;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import okio.x;
import org.xmlpull.v1.XmlPullParser;

/* loaded from: classes2.dex */
public final class a implements y, l, o0, z0, c, Q0, InterfaceC1048g, InterfaceC1053j, n, D3, Pv, i, OnCompleteListener {
    public static a c;
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ a(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj2;
    }

    @Override // androidx.core.view.InterfaceC1053j
    public void A() {
        ((NestedScrollView) this.b).d.abortAnimation();
    }

    /* JADX WARN: Removed duplicated region for block: B:119:0x019f  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00c5  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public coil3.memory.b B(coil3.request.g r17, coil3.memory.a r18, coil3.size.h r19, coil3.size.g r20) {
        /*
            Method dump skipped, instructions count: 442
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.instantapps.a.B(coil3.request.g, coil3.memory.a, coil3.size.h, coil3.size.g):coil3.memory.b");
    }

    public coil3.memory.a C(g gVar, Object obj, m mVar, f fVar) throws FileNotFoundException {
        String string;
        String strF;
        gVar.getClass();
        Map map = gVar.d;
        List list = ((u) this.b).c.c;
        int size = list.size();
        int i = 0;
        while (true) {
            if (i < size) {
                Pair pair = (Pair) list.get(i);
                coil3.key.a aVar = (coil3.key.a) pair.a;
                if (((C4950i) ((kotlin.reflect.c) pair.b)).g(obj)) {
                    Intrinsics.e(aVar, "null cannot be cast to non-null type coil3.key.Keyer<kotlin.Any>");
                    switch (aVar.a) {
                        case 0:
                            coil3.y yVar = (coil3.y) obj;
                            if (!Intrinsics.b(yVar.c, "android.resource")) {
                                string = null;
                                break;
                            } else {
                                StringBuilder sb = new StringBuilder();
                                sb.append(yVar);
                                sb.append(':');
                                Configuration configuration = mVar.a.getResources().getConfiguration();
                                Bitmap.Config[] configArr = coil3.util.l.a;
                                sb.append(configuration.uiMode & 48);
                                string = sb.toString();
                                break;
                            }
                        case 1:
                            coil3.y yVar2 = (coil3.y) obj;
                            String str = yVar2.c;
                            if ((str == null || str.equals("file")) && yVar2.e != null) {
                                Bitmap.Config[] configArr2 = coil3.util.l.a;
                                if ((!Intrinsics.b(yVar2.c, "file") || !Intrinsics.b(CollectionsKt.firstOrNull(coil3.n.g(yVar2)), "android_asset")) && ((Boolean) coil3.n.e(mVar, h.c)).booleanValue() && (strF = coil3.n.f(yVar2)) != null) {
                                    String str2 = x.b;
                                    androidx.constraintlayout.core.widgets.analyzer.f fVarY = mVar.f.y(com.quizlet.quizletandroid.ui.folder.logging.a.f(strF, false));
                                    StringBuilder sb2 = new StringBuilder();
                                    sb2.append(yVar2);
                                    sb2.append('-');
                                    sb2.append((Long) fVarY.g);
                                    string = sb2.toString();
                                    break;
                                }
                            }
                            string = null;
                            break;
                        default:
                            string = ((coil3.y) obj).a;
                            break;
                    }
                    if (string != null) {
                    }
                }
                i++;
            } else {
                string = null;
            }
        }
        if (string == null) {
            return null;
        }
        if (((List) coil3.n.d(gVar, h.a)).isEmpty()) {
            return new coil3.memory.a(string, map);
        }
        LinkedHashMap linkedHashMapM = V.m(map);
        linkedHashMapM.put("coil#size", mVar.b.toString());
        return new coil3.memory.a(string, linkedHashMapM);
    }

    @Override // androidx.appcompat.view.menu.l
    public void D(androidx.appcompat.view.menu.n nVar) {
        l lVar = ((ActionMenuView) this.b).v;
        if (lVar != null) {
            lVar.D(nVar);
        }
    }

    public synchronized void E(com.bumptech.glide.gifdecoder.c cVar) {
        cVar.b = null;
        cVar.c = null;
        ((ArrayDeque) this.b).offer(cVar);
    }

    public Object F() {
        if (AbstractC2937a.b == null) {
            AbstractC2937a.b = new C1756Qb();
        }
        synchronized (AbstractC2937a.a) {
        }
        throw new IllegalStateException("Must call PhenotypeContext.setContext() first");
    }

    public void G(int i, String str, List list, boolean z, boolean z2) {
        C1719Ka c1719Ka;
        int i2 = i - 1;
        T t = (T) this.b;
        if (i2 == 0) {
            I i3 = ((Y) t.b).i;
            Y.k(i3);
            c1719Ka = i3.n;
        } else if (i2 != 1) {
            if (i2 == 3) {
                I i4 = ((Y) t.b).i;
                Y.k(i4);
                c1719Ka = i4.o;
            } else if (i2 != 4) {
                I i5 = ((Y) t.b).i;
                Y.k(i5);
                c1719Ka = i5.m;
            } else if (z) {
                I i6 = ((Y) t.b).i;
                Y.k(i6);
                c1719Ka = i6.k;
            } else if (z2) {
                I i7 = ((Y) t.b).i;
                Y.k(i7);
                c1719Ka = i7.j;
            } else {
                I i8 = ((Y) t.b).i;
                Y.k(i8);
                c1719Ka = i8.l;
            }
        } else if (z) {
            I i9 = ((Y) t.b).i;
            Y.k(i9);
            c1719Ka = i9.h;
        } else if (z2) {
            I i10 = ((Y) t.b).i;
            Y.k(i10);
            c1719Ka = i10.g;
        } else {
            I i11 = ((Y) t.b).i;
            Y.k(i11);
            c1719Ka = i11.i;
        }
        int size = list.size();
        if (size == 1) {
            c1719Ka.g(str, list.get(0));
            return;
        }
        if (size == 2) {
            c1719Ka.h(str, list.get(0), list.get(1));
        } else if (size != 3) {
            c1719Ka.f(str);
        } else {
            c1719Ka.i(str, list.get(0), list.get(1), list.get(2));
        }
    }

    @Override // androidx.compose.animation.core.Q0, androidx.compose.animation.core.N0
    public boolean a() {
        ((com.quizlet.data.interactor.progress.c) this.b).getClass();
        return false;
    }

    @Override // com.google.android.gms.common.api.internal.i
    public void accept(Object obj, Object obj2) {
        com.google.android.gms.common.moduleinstall.internal.c cVar = new com.google.android.gms.common.moduleinstall.internal.c((com.google.android.gms.tasks.f) obj2, 0);
        b bVar = (b) ((e) obj).m();
        Parcel parcelObtain = Parcel.obtain();
        parcelObtain.writeInterfaceToken(bVar.c);
        com.google.android.gms.internal.base.a.c(parcelObtain, cVar);
        com.google.android.gms.internal.base.a.b(parcelObtain, (ApiFeatureRequest) this.b);
        bVar.V(1, parcelObtain);
    }

    @Override // androidx.compose.animation.core.N0
    public long b(AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return ((com.quizlet.data.interactor.progress.c) this.b).b(abstractC0267t, abstractC0267t2, abstractC0267t3);
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        C2661ti c2661ti = (C2661ti) this.b;
        q qVar = (q) obj;
        synchronized (c2661ti) {
            c2661ti.j1(new C2881yn(qVar, 16));
        }
    }

    @Override // androidx.camera.camera2.internal.o0
    public void d(TotalCaptureResult totalCaptureResult) {
    }

    @Override // androidx.appcompat.view.menu.y
    public void e(androidx.appcompat.view.menu.n nVar, boolean z) {
        A a;
        androidx.appcompat.view.menu.n nVarK = nVar.k();
        int i = 0;
        boolean z2 = nVarK != nVar;
        if (z2) {
            nVar = nVarK;
        }
        B b = (B) this.b;
        A[] aArr = b.L;
        int length = aArr != null ? aArr.length : 0;
        while (true) {
            if (i < length) {
                a = aArr[i];
                if (a != null && a.h == nVar) {
                    break;
                } else {
                    i++;
                }
            } else {
                a = null;
                break;
            }
        }
        if (a != null) {
            if (!z2) {
                b.s(a, z);
            } else {
                b.p(a.a, a, nVarK);
                b.s(a, true);
            }
        }
    }

    @Override // androidx.core.view.InterfaceC1048g
    public ClipData f() {
        return ((ContentInfo) this.b).getClip();
    }

    @Override // androidx.core.view.accessibility.n
    public boolean g(View view) {
        switch (this.a) {
            case 16:
                int currentItem = ((ViewPager2) view).getCurrentItem() - 1;
                ViewPager2 viewPager2 = (ViewPager2) ((androidx.work.impl.model.n) this.b).d;
                if (viewPager2.r) {
                    viewPager2.c(currentItem);
                }
                return true;
            default:
                SwipeDismissBehavior swipeDismissBehavior = (SwipeDismissBehavior) this.b;
                if (!swipeDismissBehavior.w(view)) {
                    return false;
                }
                WeakHashMap weakHashMap = androidx.core.view.V.a;
                boolean z = view.getLayoutDirection() == 1;
                int i = swipeDismissBehavior.e;
                view.offsetLeftAndRight((!(i == 0 && z) && (i != 1 || z)) ? view.getWidth() : -view.getWidth());
                view.setAlpha(DefinitionKt.NO_Float_VALUE);
                d dVar = swipeDismissBehavior.b;
                if (dVar == null) {
                    return true;
                }
                dVar.m(view);
                return true;
        }
    }

    @Override // androidx.camera.camera2.internal.o0
    public void h(androidx.camera.camera2.impl.a aVar) {
    }

    @Override // androidx.camera.camera2.internal.o0
    public float i() {
        Float f = (Float) ((k) this.b).a(CameraCharacteristics.SCALER_AVAILABLE_MAX_DIGITAL_ZOOM);
        if (f != null && f.floatValue() >= 1.0f) {
            return f.floatValue();
        }
        return 1.0f;
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t j(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return ((com.quizlet.data.interactor.progress.c) this.b).j(j, abstractC0267t, abstractC0267t2, abstractC0267t3);
    }

    @Override // androidx.core.view.InterfaceC1053j
    public boolean k(float f) {
        if (f == DefinitionKt.NO_Float_VALUE) {
            return false;
        }
        A();
        ((NestedScrollView) this.b).k((int) f);
        return true;
    }

    @Override // androidx.camera.camera2.internal.o0
    public float l() {
        return 1.0f;
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t n(AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return ((com.quizlet.data.interactor.progress.c) this.b).n(abstractC0267t, abstractC0267t2, abstractC0267t3);
    }

    @Override // androidx.core.view.InterfaceC1048g
    public int o() {
        return ((ContentInfo) this.b).getFlags();
    }

    @Override // com.google.android.gms.tasks.OnCompleteListener
    public void onComplete(Task task) {
        OssLicensesMenuActivity ossLicensesMenuActivity = (OssLicensesMenuActivity) this.b;
        String packageName = ossLicensesMenuActivity.getPackageName();
        if (ossLicensesMenuActivity.isDestroyed() || ossLicensesMenuActivity.isFinishing()) {
            return;
        }
        if (task.l()) {
            packageName = (String) task.h();
        }
        ossLicensesMenuActivity.f = com.quizlet.data.interactor.school.b.p(ossLicensesMenuActivity, packageName);
        LayoutInflater layoutInflater = ossLicensesMenuActivity.getLayoutInflater();
        v vVar = ossLicensesMenuActivity.f;
        Resources resources = (Resources) vVar.b;
        ossLicensesMenuActivity.setContentView(layoutInflater.inflate((XmlPullParser) resources.getXml(resources.getIdentifier("libraries_social_licenses_license_menu_activity", "layout", (String) vVar.c)), (ViewGroup) null, false));
        v vVar2 = ossLicensesMenuActivity.f;
        ossLicensesMenuActivity.c = (ListView) ossLicensesMenuActivity.findViewById(((Resources) vVar2.b).getIdentifier("license_list", "id", (String) vVar2.c));
        com.google.android.gms.oss.licenses.e eVar = new com.google.android.gms.oss.licenses.e(ossLicensesMenuActivity, ossLicensesMenuActivity);
        ossLicensesMenuActivity.d = eVar;
        ossLicensesMenuActivity.c.setAdapter((ListAdapter) eVar);
        ossLicensesMenuActivity.c.setOnItemClickListener(new M(this, 2));
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
        ((androidx.concurrent.futures.i) this.b).d(th);
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) this.b;
        try {
            iVar.b(obj);
        } catch (Throwable th) {
            iVar.d(th);
        }
    }

    @Override // androidx.core.view.InterfaceC1048g
    public ContentInfo p() {
        return (ContentInfo) this.b;
    }

    @Override // androidx.camera.core.InterfaceC0197u
    public W q() {
        return (X) this.b;
    }

    @Override // androidx.appcompat.view.menu.l
    public boolean r(androidx.appcompat.view.menu.n nVar, MenuItem menuItem) {
        boolean zOnMenuItemSelected;
        InterfaceC0101o interfaceC0101o = ((ActionMenuView) this.b).A;
        if (interfaceC0101o != null) {
            Toolbar toolbar = (Toolbar) ((L) interfaceC0101o).b;
            if (toolbar.G.a(menuItem)) {
                zOnMenuItemSelected = true;
            } else {
                u1 u1Var = toolbar.I;
                zOnMenuItemSelected = u1Var != null ? ((androidx.appcompat.app.M) ((com.google.firebase.platforminfo.c) u1Var).a).b.onMenuItemSelected(0, menuItem) : false;
            }
            if (zOnMenuItemSelected) {
                return true;
            }
        }
        return false;
    }

    @Override // androidx.camera.core.impl.z0
    public A0 s() {
        return new C0165d0(C0163c0.a((X) this.b));
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t t(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return ((com.quizlet.data.interactor.progress.c) this.b).t(j, abstractC0267t, abstractC0267t2, abstractC0267t3);
    }

    public String toString() {
        switch (this.a) {
            case 12:
                return "ContentInfoCompat{" + ((ContentInfo) this.b) + "}";
            default:
                return super.toString();
        }
    }

    @Override // androidx.core.view.InterfaceC1048g
    public int v() {
        return ((ContentInfo) this.b).getSource();
    }

    @Override // androidx.core.view.InterfaceC1053j
    public float w() {
        return -((NestedScrollView) this.b).getVerticalScrollFactorCompat();
    }

    @Override // com.google.android.gms.internal.ads.D3
    public void x(zzaqd zzaqdVar) {
        ((C2313ld) this.b).d(zzaqdVar);
    }

    @Override // androidx.camera.camera2.internal.o0
    public void y() {
    }

    @Override // androidx.appcompat.view.menu.y
    public boolean z(androidx.appcompat.view.menu.n nVar) {
        Window.Callback callback;
        if (nVar != nVar.k()) {
            return true;
        }
        B b = (B) this.b;
        if (!b.F || (callback = b.l.getCallback()) == null || b.Y) {
            return true;
        }
        callback.onMenuOpened(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY, nVar);
        return true;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        C2661ti c2661ti = (C2661ti) this.b;
        String message = th.getMessage();
        synchronized (c2661ti) {
            c2661ti.j1(new Ew(message, 5));
        }
    }

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public a(u uVar, com.quizlet.data.repository.activitycenter.b bVar) {
        this.a = 18;
        this.b = uVar;
    }

    public a(WorkDatabase workDatabase) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(workDatabase, "workDatabase");
        this.b = workDatabase;
    }

    public a(int i) {
        Object bVar;
        this.a = i;
        switch (i) {
            case 6:
                this(X.b());
                break;
            case 11:
                if (Build.VERSION.SDK_INT >= 28) {
                    bVar = new retrofit2.adapter.rxjava3.d(2);
                } else {
                    bVar = new assistantMode.utils.studiableMetadata.b(3);
                }
                this.b = bVar;
                break;
            case 15:
                com.quizlet.data.repository.studysetwithcreator.d dVar = new com.quizlet.data.repository.studysetwithcreator.d();
                dVar.a = new C1352z();
                dVar.b = new C1352z();
                dVar.d = new ReentrantLock();
                this.b = dVar;
                break;
            case 21:
                char[] cArr = com.bumptech.glide.util.m.a;
                this.b = new ArrayDeque(0);
                break;
        }
    }

    public a(ContentInfo contentInfo) {
        this.a = 12;
        contentInfo.getClass();
        this.b = AbstractC1042d.q(contentInfo);
    }

    public a(X x) {
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
        if (cls != null && !cls.equals(androidx.camera.core.X.class)) {
            throw new IllegalArgumentException("Invalid target class configuration for " + this + ": " + cls);
        }
        ((X) this.b).m(A0.v0, C0.b);
        C0162c c0162c = androidx.camera.core.internal.k.A0;
        X x2 = (X) this.b;
        x2.m(c0162c, androidx.camera.core.X.class);
        try {
            objE2 = x2.e(androidx.camera.core.internal.k.z0);
        } catch (IllegalArgumentException unused2) {
        }
        if (objE2 == null) {
            ((X) this.b).m(androidx.camera.core.internal.k.z0, androidx.camera.core.X.class.getCanonicalName() + "-" + UUID.randomUUID());
        }
        Object objE3 = -1;
        try {
            objE3 = x.e(P.g0);
        } catch (IllegalArgumentException unused3) {
        }
        if (((Integer) objE3).intValue() == -1) {
            x.m(P.g0, 2);
        }
    }

    public a(float f, float f2, AbstractC0267t abstractC0267t) {
        InterfaceC0269u dVar;
        this.a = 8;
        if (abstractC0267t != null) {
            dVar = new O0(f, f2, abstractC0267t);
        } else {
            dVar = new d(f, f2);
        }
        this.b = new com.quizlet.data.interactor.progress.c(dVar);
    }
}
