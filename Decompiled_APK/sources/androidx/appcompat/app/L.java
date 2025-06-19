package androidx.appcompat.app;

import android.R;
import android.animation.AnimatorSet;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import android.text.TextUtils;
import android.util.Log;
import android.util.Size;
import android.view.MenuItem;
import android.view.Surface;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import androidx.appcompat.widget.InterfaceC0101o;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.C0143u;
import androidx.camera.camera2.internal.c0;
import androidx.camera.camera2.internal.compat.quirk.AeFpsRangeLegacyQuirk;
import androidx.camera.core.b0;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.InterfaceC0177p;
import androidx.camera.core.impl.W;
import androidx.camera.core.impl.X;
import androidx.camera.core.impl.i0;
import androidx.camera.core.impl.j0;
import androidx.camera.core.impl.v0;
import androidx.camera.core.impl.z0;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0276z;
import androidx.compose.animation.d0;
import androidx.compose.foundation.gestures.G0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.W0;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.core.view.D0;
import androidx.core.view.RunnableC1068z;
import androidx.work.rxjava3.RxWorker;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1732Mb;
import com.google.android.gms.internal.ads.C2580rn;
import com.google.android.gms.internal.ads.U7;
import com.google.android.gms.internal.fido.AbstractC2946j;
import com.google.android.gms.internal.fido.k0;
import com.google.android.gms.internal.fido.l0;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.material.bottomappbar.BottomAppBar;
import com.google.gson.JsonIOException;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class L implements androidx.appcompat.view.menu.l, InterfaceC0101o, androidx.camera.core.impl.utils.futures.c, j0, androidx.camera.core.impl.S, z0, androidx.compose.foundation.gestures.snapping.b, io.reactivex.rxjava3.core.q, com.google.android.gms.common.api.internal.i, com.google.android.gms.tasks.d, com.google.android.material.internal.s, com.google.android.material.internal.h, com.google.gson.internal.n {
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ L(int i) {
        this.a = i;
    }

    public static b0 I(androidx.camera.core.O o) {
        if (o == null) {
            return null;
        }
        return new b0(o, new Size(o.getWidth(), o.b()), new androidx.camera.core.internal.c(new com.quizlet.data.interactor.course.c((InterfaceC0177p) null, v0.b, o.N().a())));
    }

    public static void J(Context context, com.google.android.gms.ads.g gVar, com.google.android.gms.ads.query.a aVar) {
        AbstractC2773w7.a(context);
        if (((Boolean) U7.j.o()).booleanValue()) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.hb)).booleanValue()) {
                com.google.android.gms.ads.internal.util.client.a.b.execute(new androidx.core.provider.k(context, gVar, aVar, 9));
                return;
            }
        }
        new C1732Mb(0, context, gVar.zza()).l(aVar);
    }

    @Override // androidx.compose.foundation.gestures.snapping.b
    public Object B(G0 g0, Float f, Float f2, androidx.compose.foundation.gestures.snapping.d dVar, androidx.compose.foundation.gestures.snapping.g gVar) {
        Object objA = androidx.compose.foundation.gestures.snapping.l.a(g0, f.floatValue(), AbstractC0240f.b(DefinitionKt.NO_Float_VALUE, f2.floatValue(), 28), (C0276z) this.b, dVar, gVar);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : (androidx.compose.foundation.gestures.snapping.a) objA;
    }

    @Override // androidx.camera.core.impl.S
    public int C() {
        return ((com.bumptech.glide.manager.p) this.b).C();
    }

    @Override // androidx.appcompat.view.menu.l
    public void D(androidx.appcompat.view.menu.n nVar) {
        M m = (M) this.b;
        boolean zP = m.a.a.p();
        w wVar = m.b;
        if (zP) {
            wVar.onPanelClosed(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY, nVar);
        } else if (wVar.onPreparePanel(0, null, nVar)) {
            wVar.onMenuOpened(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY, nVar);
        }
    }

    @Override // com.google.gson.internal.n
    public Object E() {
        Type type = (Type) this.b;
        if (!(type instanceof ParameterizedType)) {
            throw new JsonIOException("Invalid EnumSet type: " + type.toString());
        }
        Type type2 = ((ParameterizedType) type).getActualTypeArguments()[0];
        if (type2 instanceof Class) {
            return EnumSet.noneOf((Class) type2);
        }
        throw new JsonIOException("Invalid EnumSet type: " + type.toString());
    }

    @Override // androidx.camera.core.impl.S
    public androidx.camera.core.O F() {
        return I(((com.bumptech.glide.manager.p) this.b).F());
    }

    @Override // androidx.camera.core.impl.S
    public void G(androidx.camera.core.impl.Q q, Executor executor) {
        ((com.bumptech.glide.manager.p) this.b).G(new C0143u(6, this, q), executor);
    }

    public void H(float f, float f2, float f3, float f4, int i) {
        ((com.quizlet.data.repository.folderset.c) this.b).o().o(f, f2, f3, f4, i);
    }

    public W0 K() {
        androidx.emoji2.text.j jVarA = androidx.emoji2.text.j.a();
        if (jVarA.b() == 1) {
            return new androidx.compose.ui.text.platform.j(true);
        }
        InterfaceC0773a0 interfaceC0773a0Z = C0776c.z(Boolean.FALSE);
        jVarA.g(new androidx.compose.ui.text.platform.f(interfaceC0773a0Z, this));
        return interfaceC0773a0Z;
    }

    public void L() {
        View view = (View) this.b;
        if (view != null) {
            ((InputMethodManager) view.getContext().getSystemService("input_method")).hideSoftInputFromWindow(view.getWindowToken(), 0);
        }
    }

    public void M(float f, float f2, float f3, float f4) {
        com.quizlet.data.repository.folderset.c cVar = (com.quizlet.data.repository.folderset.c) this.b;
        InterfaceC0858s interfaceC0858sO = cVar.o();
        long jA = T4.a(androidx.compose.ui.geometry.e.d(cVar.r()) - (f3 + f), androidx.compose.ui.geometry.e.b(cVar.r()) - (f4 + f2));
        if (androidx.compose.ui.geometry.e.d(jA) < DefinitionKt.NO_Float_VALUE || androidx.compose.ui.geometry.e.b(jA) < DefinitionKt.NO_Float_VALUE) {
            throw new IllegalArgumentException("Width and height must be greater than or equal to zero");
        }
        cVar.y(jA);
        interfaceC0858sO.p(f, f2);
    }

    public JSONObject N() throws Throwable {
        Throwable th;
        FileInputStream fileInputStream;
        JSONObject jSONObject;
        Log.isLoggable("FirebaseCrashlytics", 3);
        FileInputStream fileInputStream2 = null;
        try {
            try {
                File file = (File) this.b;
                if (file.exists()) {
                    fileInputStream = new FileInputStream(file);
                    try {
                        jSONObject = new JSONObject(com.google.firebase.crashlytics.internal.common.f.i(fileInputStream));
                        fileInputStream2 = fileInputStream;
                    } catch (Exception e) {
                        e = e;
                        Log.e("FirebaseCrashlytics", "Failed to fetch cached settings", e);
                        com.google.firebase.crashlytics.internal.common.f.b(fileInputStream, "Error while closing settings cache file.");
                        return null;
                    }
                } else {
                    Log.isLoggable("FirebaseCrashlytics", 2);
                    jSONObject = null;
                }
                com.google.firebase.crashlytics.internal.common.f.b(fileInputStream2, "Error while closing settings cache file.");
                return jSONObject;
            } catch (Throwable th2) {
                th = th2;
                com.google.firebase.crashlytics.internal.common.f.b(null, "Error while closing settings cache file.");
                throw th;
            }
        } catch (Exception e2) {
            e = e2;
            fileInputStream = null;
        } catch (Throwable th3) {
            th = th3;
            com.google.firebase.crashlytics.internal.common.f.b(null, "Error while closing settings cache file.");
            throw th;
        }
    }

    public void O(long j, float f) {
        InterfaceC0858s interfaceC0858sO = ((com.quizlet.data.repository.folderset.c) this.b).o();
        interfaceC0858sO.p(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j));
        interfaceC0858sO.b(f);
        interfaceC0858sO.p(-androidx.compose.ui.geometry.b.d(j), -androidx.compose.ui.geometry.b.e(j));
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0050  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object P(int r5, kotlin.jvm.functions.Function1 r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof androidx.paging.e1
            if (r0 == 0) goto L13
            r0 = r7
            androidx.paging.e1 r0 = (androidx.paging.e1) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.paging.e1 r0 = new androidx.paging.e1
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.appcompat.app.L r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: androidx.paging.b1 -> L29
            goto L4d
        L29:
            r6 = move-exception
            goto L49
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            androidx.paging.f1 r7 = new androidx.paging.f1     // Catch: androidx.paging.b1 -> L47
            r2 = 0
            r7.<init>(r4, r5, r6, r2)     // Catch: androidx.paging.b1 -> L47
            r0.j = r4     // Catch: androidx.paging.b1 -> L47
            r0.m = r3     // Catch: androidx.paging.b1 -> L47
            java.lang.Object r5 = kotlinx.coroutines.E.m(r7, r0)     // Catch: androidx.paging.b1 -> L47
            if (r5 != r1) goto L4d
            return r1
        L47:
            r6 = move-exception
            r5 = r4
        L49:
            androidx.appcompat.app.L r7 = r6.a
            if (r7 != r5) goto L50
        L4d:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L50:
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.L.P(int, kotlin.jvm.functions.Function1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void Q(float f, float f2, long j) {
        InterfaceC0858s interfaceC0858sO = ((com.quizlet.data.repository.folderset.c) this.b).o();
        interfaceC0858sO.p(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j));
        interfaceC0858sO.a(f, f2);
        interfaceC0858sO.p(-androidx.compose.ui.geometry.b.d(j), -androidx.compose.ui.geometry.b.e(j));
    }

    public void R() {
        View viewFindViewById;
        View view = (View) this.b;
        if (view == null) {
            return;
        }
        if (view.isInEditMode() || view.onCheckIsTextEditor()) {
            view.requestFocus();
            viewFindViewById = view;
        } else {
            viewFindViewById = view.getRootView().findFocus();
        }
        if (viewFindViewById == null) {
            viewFindViewById = view.getRootView().findViewById(R.id.content);
        }
        if (viewFindViewById == null || !viewFindViewById.hasWindowFocus()) {
            return;
        }
        viewFindViewById.post(new RunnableC1068z(viewFindViewById, 0));
    }

    public void S(float f, float f2) {
        ((com.quizlet.data.repository.folderset.c) this.b).o().p(f, f2);
    }

    public boolean T() {
        Y y = (Y) this.b;
        if (!TextUtils.isEmpty(y.b)) {
            return false;
        }
        com.google.android.gms.measurement.internal.I i = y.i;
        Y.k(i);
        return Log.isLoggable(i.d0(), 3);
    }

    @Override // io.reactivex.rxjava3.core.q
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        Objects.requireNonNull(bVar);
        ((androidx.concurrent.futures.i) this.b).a(new androidx.compose.ui.text.input.C(bVar, 9), RxWorker.e);
    }

    @Override // com.google.android.gms.common.api.internal.i
    public void accept(Object obj, Object obj2) {
        com.google.android.gms.fido.fido2.b bVar = new com.google.android.gms.fido.fido2.b((com.google.android.gms.tasks.f) obj2, 0);
        l0 l0Var = (l0) ((k0) obj).m();
        Parcel parcelObtain = Parcel.obtain();
        parcelObtain.writeInterfaceToken(l0Var.b);
        int i = AbstractC2946j.a;
        parcelObtain.writeStrongBinder(bVar);
        PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = (PublicKeyCredentialCreationOptions) this.b;
        parcelObtain.writeInt(1);
        publicKeyCredentialCreationOptions.writeToParcel(parcelObtain, 0);
        Parcel parcelObtain2 = Parcel.obtain();
        try {
            l0Var.a.transact(1, parcelObtain, parcelObtain2, 0);
            parcelObtain2.readException();
        } finally {
            parcelObtain.recycle();
            parcelObtain2.recycle();
        }
    }

    @Override // androidx.camera.core.impl.S
    public int b() {
        return ((com.bumptech.glide.manager.p) this.b).b();
    }

    @Override // androidx.camera.core.impl.S
    public void close() {
        ((com.bumptech.glide.manager.p) this.b).close();
    }

    @Override // androidx.camera.core.impl.S
    public int getWidth() {
        return ((com.bumptech.glide.manager.p) this.b).getWidth();
    }

    @Override // com.google.android.material.internal.s
    public D0 k(View view, D0 d0, com.google.android.gms.ads.internal.overlay.k kVar) {
        boolean z;
        BottomAppBar bottomAppBar = (BottomAppBar) this.b;
        if (bottomAppBar.t1) {
            bottomAppBar.z1 = d0.a();
        }
        boolean z2 = false;
        if (bottomAppBar.u1) {
            z = bottomAppBar.B1 != d0.b();
            bottomAppBar.B1 = d0.b();
        } else {
            z = false;
        }
        if (bottomAppBar.v1) {
            boolean z3 = bottomAppBar.A1 != d0.c();
            bottomAppBar.A1 = d0.c();
            z2 = z3;
        }
        if (!z && !z2) {
            return d0;
        }
        AnimatorSet animatorSet = bottomAppBar.k1;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        AnimatorSet animatorSet2 = bottomAppBar.j1;
        if (animatorSet2 != null) {
            animatorSet2.cancel();
        }
        bottomAppBar.I();
        bottomAppBar.H();
        return d0;
    }

    @Override // androidx.camera.core.impl.S
    public androidx.camera.core.O l() {
        return I(((com.bumptech.glide.manager.p) this.b).l());
    }

    @Override // androidx.camera.core.impl.S
    public int m() {
        return ((com.bumptech.glide.manager.p) this.b).m();
    }

    @Override // androidx.camera.core.impl.j0
    public androidx.camera.core.impl.H n() {
        return (androidx.camera.core.impl.H) this.b;
    }

    @Override // io.reactivex.rxjava3.core.q
    public void onError(Throwable th) {
        ((androidx.concurrent.futures.i) this.b).d(th);
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
        androidx.camera.camera2.internal.k0 k0Var;
        androidx.camera.camera2.internal.k0 k0Var2 = (androidx.camera.camera2.internal.k0) this.b;
        synchronized (k0Var2.a) {
            try {
                List list = k0Var2.k;
                if (list != null) {
                    Iterator it2 = list.iterator();
                    while (it2.hasNext()) {
                        ((androidx.camera.core.impl.J) it2.next()).b();
                    }
                    k0Var2.k = null;
                }
            } finally {
            }
        }
        k0Var2.u.J();
        c0 c0Var = k0Var2.b;
        Iterator it3 = c0Var.q().iterator();
        while (it3.hasNext() && (k0Var = (androidx.camera.camera2.internal.k0) it3.next()) != k0Var2) {
            synchronized (k0Var.a) {
                try {
                    List list2 = k0Var.k;
                    if (list2 != null) {
                        Iterator it4 = list2.iterator();
                        while (it4.hasNext()) {
                            ((androidx.camera.core.impl.J) it4.next()).b();
                        }
                        k0Var.k = null;
                    }
                } finally {
                }
            }
            k0Var.u.J();
        }
        synchronized (c0Var.c) {
            ((LinkedHashSet) c0Var.f).remove(k0Var2);
        }
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        switch (this.a) {
            case 2:
                break;
            case 14:
                ((androidx.concurrent.futures.i) this.b).b(obj);
                break;
            default:
                ((com.google.android.gms.tasks.f) ((androidx.webkit.internal.p) this.b).b).a.s();
                break;
        }
    }

    @Override // androidx.camera.core.impl.S
    public void p() {
        ((com.bumptech.glide.manager.p) this.b).p();
    }

    @Override // androidx.camera.core.InterfaceC0197u
    public W q() {
        return (X) this.b;
    }

    @Override // androidx.appcompat.view.menu.l
    public boolean r(androidx.appcompat.view.menu.n nVar, MenuItem menuItem) {
        return false;
    }

    @Override // androidx.camera.core.impl.z0
    public A0 s() {
        return new androidx.camera.core.streamsharing.e(C0163c0.a((X) this.b));
    }

    @Override // androidx.camera.core.impl.S
    public Surface w() {
        return ((com.bumptech.glide.manager.p) this.b).w();
    }

    public /* synthetic */ L(com.google.android.gms.fido.fido2.a aVar, PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions) {
        this.a = 21;
        this.b = publicKeyCredentialCreationOptions;
    }

    public /* synthetic */ L(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public L() {
        this.a = 15;
        this.b = new HashSet();
    }

    public L(com.bumptech.glide.f fVar) {
        this.a = 17;
        this.b = Collections.unmodifiableMap(new HashMap(fVar.a));
    }

    public L(Bundle bundle, String action) {
        Uri uriA;
        String str;
        this.a = 18;
        Intrinsics.checkNotNullParameter(action, "action");
        bundle = bundle == null ? new Bundle() : bundle;
        int[] iArrN = AbstractC0147y.n(2);
        ArrayList arrayList = new ArrayList(iArrN.length);
        for (int i : iArrN) {
            if (i == 1) {
                str = "context_choose";
            } else {
                if (i != 2) {
                    throw null;
                }
                str = "join_tournament";
            }
            arrayList.add(str);
        }
        if (arrayList.contains(action)) {
            com.facebook.o oVar = com.facebook.o.a;
            uriA = com.facebook.internal.J.a(d0.s(new Object[]{"fb.gg"}, 1, "%s", "format(format, *args)"), "/dialog/".concat(action), bundle);
        } else {
            Intrinsics.checkNotNullParameter(action, "action");
            uriA = com.facebook.internal.J.a(com.facebook.internal.J.p(), com.facebook.o.d() + "/dialog/" + action, bundle);
        }
        this.b = uriA;
    }

    public L(com.google.firebase.crashlytics.internal.persistence.c cVar) {
        this.a = 28;
        this.b = new File(cVar.c, "com.crashlytics.settings.json");
    }

    public L(boolean z) {
        this.a = 12;
        this.b = new C2580rn(this, z);
    }

    public L(i0 i0Var) {
        this.a = 3;
        AeFpsRangeLegacyQuirk aeFpsRangeLegacyQuirk = (AeFpsRangeLegacyQuirk) i0Var.b(AeFpsRangeLegacyQuirk.class);
        if (aeFpsRangeLegacyQuirk == null) {
            this.b = null;
        } else {
            this.b = aeFpsRangeLegacyQuirk.a;
        }
    }

    public L(X x) {
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
        if (cls != null && !cls.equals(androidx.camera.core.streamsharing.d.class)) {
            throw new IllegalArgumentException("Invalid target class configuration for " + this + ": " + cls);
        }
        ((X) this.b).m(A0.v0, C0.e);
        C0162c c0162c = androidx.camera.core.internal.k.A0;
        X x2 = (X) this.b;
        x2.m(c0162c, androidx.camera.core.streamsharing.d.class);
        try {
            objE2 = x2.e(androidx.camera.core.internal.k.z0);
        } catch (IllegalArgumentException unused2) {
        }
        if (objE2 == null) {
            x2.m(androidx.camera.core.internal.k.z0, androidx.camera.core.streamsharing.d.class.getCanonicalName() + "-" + UUID.randomUUID());
        }
    }
}
