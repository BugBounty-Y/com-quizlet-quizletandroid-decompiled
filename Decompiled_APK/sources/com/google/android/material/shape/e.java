package com.google.android.material.shape;

import android.content.Context;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.media.CamcorderProfile;
import android.os.Looper;
import android.view.View;
import androidx.camera.camera2.internal.InterfaceC0127d;
import androidx.camera.camera2.internal.c0;
import androidx.camera.camera2.internal.m0;
import androidx.fragment.app.I;
import com.facebook.z;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.measurement.B3;
import com.google.android.gms.internal.measurement.D3;
import com.google.android.gms.internal.measurement.E3;
import com.google.android.gms.internal.measurement.G3;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.quizlet.learn.data.C4537b;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class e implements InterfaceC0127d, androidx.arch.core.util.a, androidx.sqlite.db.d, com.bumptech.glide.manager.f, com.google.android.gms.measurement.internal.r, com.google.gson.internal.n, com.google.firebase.components.d, io.reactivex.rxjava3.functions.g {
    public final /* synthetic */ int a;

    public /* synthetic */ e(int i) {
        this.a = i;
    }

    public static com.perimeterx.mobile_sdk.models.e h(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        com.perimeterx.mobile_sdk.models.e eVar = com.perimeterx.mobile_sdk.models.e.b;
        if (Intrinsics.b(name, eVar.b())) {
            return eVar;
        }
        com.perimeterx.mobile_sdk.models.e eVar2 = com.perimeterx.mobile_sdk.models.e.c;
        if (Intrinsics.b(name, eVar2.b())) {
            return eVar2;
        }
        com.perimeterx.mobile_sdk.models.e eVar3 = com.perimeterx.mobile_sdk.models.e.d;
        if (Intrinsics.b(name, eVar3.b())) {
            return eVar3;
        }
        return null;
    }

    public static com.quizlet.data.repository.user.e i(com.quizlet.data.repository.user.e eVar, com.quizlet.data.repository.user.e eVar2, androidx.room.s sVar) {
        if (sVar == null) {
            q(eVar, eVar2);
            return eVar;
        }
        androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) eVar.b;
        androidx.navigation.internal.m mVar2 = (androidx.navigation.internal.m) eVar2.b;
        String strK = k((String) mVar.f, (String) mVar2.f);
        if (strK != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK)) {
            mVar.f = strK;
        }
        String strK2 = k((String) mVar.b, sVar.b);
        if ((strK2 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK2)) || ((strK2 = (String) mVar2.b) != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK2))) {
            mVar.b = strK2;
        }
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) mVar.d;
        String strK3 = k((String) kVar.d, (String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d);
        if (strK3 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK3)) {
            kVar.d = strK3;
        }
        mVar.d = kVar;
        eVar.b = mVar;
        return eVar;
    }

    public static String k(String str, String str2) {
        return !com.onetrust.otpublishers.headless.Internal.a.j(str) ? str : str2;
    }

    public static void l(c0 c0Var, c0 c0Var2) {
        androidx.constraintlayout.motion.widget.n nVar = (androidx.constraintlayout.motion.widget.n) c0Var.g;
        androidx.constraintlayout.motion.widget.n nVar2 = (androidx.constraintlayout.motion.widget.n) c0Var2.g;
        n(nVar, nVar2);
        if (!AbstractC3605e0.a((String) nVar.k) && !com.onetrust.otpublishers.headless.Internal.a.j((String) nVar2.k)) {
            nVar.k = (String) nVar2.k;
        }
        String strK = k((String) nVar.e, (String) nVar2.e);
        if (strK != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK)) {
            nVar.e = strK;
        }
        c0Var.g = nVar;
        String strK2 = k((String) c0Var.f, (String) c0Var2.f);
        if (strK2 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK2)) {
            c0Var.f = strK2;
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) c0Var2.d)) {
            c0Var.d = (String) c0Var2.d;
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) c0Var2.c)) {
            c0Var.c = (String) c0Var2.c;
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) c0Var2.b)) {
            c0Var.b = (String) c0Var2.b;
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) c0Var2.e)) {
            c0Var.e = (String) c0Var2.e;
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) ((androidx.constraintlayout.motion.widget.n) c0Var2.g).j)) {
            return;
        }
        ((androidx.constraintlayout.motion.widget.n) c0Var.g).j = (String) ((androidx.constraintlayout.motion.widget.n) c0Var2.g).j;
    }

    public static void m(androidx.compose.runtime.internal.j jVar, androidx.compose.runtime.internal.j jVar2) {
        String strK = k((String) jVar.c, (String) jVar2.c);
        if (strK != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK)) {
            jVar.c = strK;
        }
        String strK2 = k((String) jVar.f, (String) jVar2.f);
        if (strK2 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK2)) {
            jVar.f = strK2;
        }
        String strK3 = k((String) jVar.d, (String) jVar2.d);
        if (strK3 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK3)) {
            jVar.d = strK3;
        }
        String strK4 = k((String) jVar.b, (String) jVar2.b);
        if (strK4 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK4)) {
            jVar.b = strK4;
        }
        String strK5 = k((String) jVar.a, (String) jVar2.a);
        if (strK5 == null || com.onetrust.otpublishers.headless.Internal.a.j(strK5)) {
            return;
        }
        jVar.a = strK5;
    }

    public static void n(androidx.constraintlayout.motion.widget.n nVar, androidx.constraintlayout.motion.widget.n nVar2) {
        String strK = k((String) nVar.i, (String) nVar2.i);
        if (strK != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK)) {
            nVar.i = strK;
        }
        String strK2 = k((String) nVar.e, (String) nVar2.e);
        if (strK2 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK2)) {
            nVar.e = strK2;
        }
        String strK3 = k(nVar.b(), nVar2.b());
        if (strK3 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK3)) {
            nVar.f = strK3;
        }
        nVar.c = nVar2.c;
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) nVar.d;
        String strK4 = k((String) kVar.d, (String) ((com.google.android.gms.cloudmessaging.k) nVar2.d).d);
        if (strK4 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK4)) {
            kVar.d = strK4;
        }
        nVar.d = kVar;
    }

    public static void o(androidx.navigation.internal.m mVar, androidx.navigation.internal.m mVar2) {
        String strK = k((String) mVar.g, (String) mVar2.g);
        if (strK != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK)) {
            mVar.g = strK;
        }
        String strK2 = k((String) mVar.f, (String) mVar2.f);
        if (strK2 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK2)) {
            mVar.f = strK2;
        }
        String strK3 = k((String) mVar.e, (String) mVar2.e);
        if (strK3 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK3)) {
            mVar.e = strK3;
        }
        String strK4 = k((String) mVar.b, (String) mVar2.b);
        if (strK4 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK4)) {
            mVar.b = strK4;
        }
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) mVar.d;
        String strK5 = k((String) kVar.d, (String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d);
        if (strK5 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK5)) {
            kVar.d = strK5;
        }
        mVar.d = kVar;
    }

    public static void p(C1608n c1608n, com.airbnb.lottie.animation.keyframe.q qVar) {
        androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) qVar.e;
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.g) && !com.onetrust.otpublishers.headless.Internal.a.j((String) c1608n.a)) {
            mVar.g = (String) c1608n.a;
            mVar.e = String.valueOf(true);
            qVar.e = mVar;
        }
        androidx.navigation.internal.m mVar2 = (androidx.navigation.internal.m) qVar.g;
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar2.g) && !com.onetrust.otpublishers.headless.Internal.a.j((String) c1608n.b)) {
            mVar2.g = (String) c1608n.b;
            mVar2.e = String.valueOf(true);
            qVar.g = mVar2;
        }
        androidx.navigation.internal.m mVar3 = (androidx.navigation.internal.m) qVar.i;
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar3.g) && !com.onetrust.otpublishers.headless.Internal.a.j((String) c1608n.c)) {
            mVar3.g = (String) c1608n.c;
            mVar3.e = String.valueOf(true);
            qVar.i = mVar3;
        }
        com.google.android.gms.internal.appset.e eVar = (com.google.android.gms.internal.appset.e) qVar.p;
        if (com.onetrust.otpublishers.headless.Internal.a.j(eVar.h()) && !com.onetrust.otpublishers.headless.Internal.a.j((String) c1608n.d)) {
            eVar.c = (String) c1608n.d;
            qVar.p = eVar;
        }
        String str = (String) c1608n.e;
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return;
        }
        qVar.d = str;
    }

    public static void q(com.quizlet.data.repository.user.e eVar, com.quizlet.data.repository.user.e eVar2) {
        androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) eVar.b;
        androidx.navigation.internal.m mVar2 = (androidx.navigation.internal.m) eVar2.b;
        String strK = k((String) mVar.f, (String) mVar2.f);
        if (strK != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK)) {
            mVar.f = strK;
        }
        String strK2 = k((String) mVar.b, (String) mVar2.b);
        if (strK2 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK2)) {
            mVar.b = strK2;
        }
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) mVar.d;
        String strK3 = k((String) kVar.d, (String) ((com.google.android.gms.cloudmessaging.k) mVar2.d).d);
        if (strK3 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK3)) {
            kVar.d = strK3;
        }
        mVar.d = kVar;
        eVar.b = mVar;
    }

    public static final float r(float f, float[] fArr, float[] fArr2) {
        float f2;
        float f3;
        float f4;
        float f5;
        float fAbs = Math.abs(f);
        float fSignum = Math.signum(f);
        int iBinarySearch = Arrays.binarySearch(fArr, fAbs);
        if (iBinarySearch >= 0) {
            return fSignum * fArr2[iBinarySearch];
        }
        int i = -(iBinarySearch + 1);
        int i2 = i - 1;
        if (i2 >= fArr.length - 1) {
            float f6 = fArr[fArr.length - 1];
            return f6 == DefinitionKt.NO_Float_VALUE ? DefinitionKt.NO_Float_VALUE : (fArr2[fArr.length - 1] / f6) * f;
        }
        if (i2 == -1) {
            float f7 = fArr[0];
            f4 = fArr2[0];
            f5 = f7;
            f3 = 0.0f;
            f2 = 0.0f;
        } else {
            float f8 = fArr[i2];
            float f9 = fArr[i];
            f2 = fArr2[i2];
            f3 = f8;
            f4 = fArr2[i];
            f5 = f9;
        }
        return (((f4 - f2) * Math.max(DefinitionKt.NO_Float_VALUE, Math.min(1.0f, f3 == f5 ? 0.0f : (fAbs - f3) / (f5 - f3)))) + f2) * fSignum;
    }

    public static RectF s(com.google.android.material.tabs.l lVar, View view) {
        if (view == null) {
            return new RectF();
        }
        if (lVar.E || !(view instanceof com.google.android.material.tabs.j)) {
            return new RectF(view.getLeft(), view.getTop(), view.getRight(), view.getBottom());
        }
        com.google.android.material.tabs.j jVar = (com.google.android.material.tabs.j) view;
        int contentWidth = jVar.getContentWidth();
        int contentHeight = jVar.getContentHeight();
        int iG = (int) com.google.android.material.internal.p.g(jVar.getContext(), 24);
        if (contentWidth < iG) {
            contentWidth = iG;
        }
        int right = (jVar.getRight() + jVar.getLeft()) / 2;
        int bottom = (jVar.getBottom() + jVar.getTop()) / 2;
        int i = contentWidth / 2;
        return new RectF(right - i, bottom - (contentHeight / 2), i + right, (right / 2) + bottom);
    }

    public static final boolean x() {
        return Looper.myLooper() == Looper.getMainLooper();
    }

    @Override // com.google.gson.internal.n
    public Object E() {
        return new ConcurrentHashMap();
    }

    @Override // androidx.arch.core.util.a
    /* renamed from: apply */
    public Object mo0apply(Object obj) {
        return obj;
    }

    @Override // androidx.camera.camera2.internal.InterfaceC0127d
    public CamcorderProfile b(int i, int i2) {
        return CamcorderProfile.get(i, i2);
    }

    @Override // com.bumptech.glide.manager.f
    public void c(I i) {
    }

    @Override // androidx.sqlite.db.d
    public androidx.sqlite.db.e d(m0 configuration) {
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        return new androidx.sqlite.db.framework.g((Context) configuration.c, (String) configuration.d, (androidx.sqlite.db.b) configuration.e, configuration.a, configuration.b);
    }

    @Override // io.reactivex.rxjava3.functions.g
    public Object e(Object t1, Object t2, Object t3, Object t4, Object t5) {
        Intrinsics.checkNotNullParameter(t1, "t1");
        Intrinsics.checkNotNullParameter(t2, "t2");
        Intrinsics.checkNotNullParameter(t3, "t3");
        Intrinsics.checkNotNullParameter(t4, "t4");
        Intrinsics.checkNotNullParameter(t5, "t5");
        return new C4537b((List) t1, (List) t2, (List) t3, (List) t4, (List) t5);
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        synchronized (com.google.android.gms.internal.mlkit_common.s.class) {
            byte b = (byte) (((byte) 1) | 2);
            if (b != 3) {
                StringBuilder sb = new StringBuilder();
                if ((b & 1) == 0) {
                    sb.append(" enableFirelog");
                }
                if ((b & 2) == 0) {
                    sb.append(" firelogEventType");
                }
                throw new IllegalStateException("Missing required properties:".concat(sb.toString()));
            }
            com.google.android.gms.internal.mlkit_common.o oVar = new com.google.android.gms.internal.mlkit_common.o();
            synchronized (com.google.android.gms.internal.mlkit_common.s.class) {
                try {
                    if (com.google.android.gms.internal.mlkit_common.s.a == null) {
                        com.google.android.gms.internal.mlkit_common.s.a = new com.google.android.gms.internal.mlkit_common.r(0);
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
            return new com.google.mlkit.common.internal.model.a(0);
        }
        return new com.google.mlkit.common.internal.model.a(0);
    }

    @Override // androidx.camera.camera2.internal.InterfaceC0127d
    public boolean g(int i, int i2) {
        return CamcorderProfile.hasProfile(i, i2);
    }

    public void t(float f, float f2, float f3, com.airbnb.lottie.value.b bVar) {
        bVar.d(f, DefinitionKt.NO_Float_VALUE);
    }

    public synchronized com.facebook.h u() {
        com.facebook.h hVar;
        try {
            if (com.facebook.h.g == null) {
                androidx.localbroadcastmanager.content.b bVarA = androidx.localbroadcastmanager.content.b.a(com.facebook.o.a());
                Intrinsics.checkNotNullExpressionValue(bVarA, "getInstance(applicationContext)");
                com.facebook.h.g = new com.facebook.h(bVarA, new z());
            }
            hVar = com.facebook.h.g;
            if (hVar == null) {
                Intrinsics.m("instance");
                throw null;
            }
        } catch (Throwable th) {
            throw th;
        }
        return hVar;
    }

    public io.reactivex.rxjava3.internal.operators.single.g v(androidx.work.impl.model.c userProps, Object obj) {
        com.quizlet.infra.legacysyncengine.features.properties.d contentProps = (com.quizlet.infra.legacysyncengine.features.properties.d) obj;
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(contentProps, "contentProps");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = com.google.android.gms.dynamite.d.e(userProps.u());
        io.reactivex.rxjava3.internal.operators.single.g gVarG = contentProps.a().g(com.quizlet.infra.legacysyncengine.features.properties.c.h);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        io.reactivex.rxjava3.internal.operators.single.g gVarG2 = contentProps.a().g(com.quizlet.infra.legacysyncengine.features.properties.c.g);
        Intrinsics.checkNotNullExpressionValue(gVarG2, "map(...)");
        return com.google.android.gms.dynamite.d.b(gVarE, com.google.android.gms.dynamite.d.f(gVarG, gVarG2));
    }

    public void w(com.google.android.material.tabs.l lVar, View view, View view2, float f, Drawable drawable) {
        RectF rectFS = s(lVar, view);
        RectF rectFS2 = s(lVar, view2);
        drawable.setBounds(com.google.android.material.animation.a.c((int) rectFS.left, f, (int) rectFS2.left), drawable.getBounds().top, com.google.android.material.animation.a.c((int) rectFS.right, f, (int) rectFS2.right), drawable.getBounds().bottom);
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 11:
                List list = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.f0.b()).longValue());
            case 12:
                List list2 = AbstractC3893t.a;
                E3.b.get();
                Boolean bool = (Boolean) G3.c.b();
                bool.getClass();
                return bool;
            case 13:
                List list3 = AbstractC3893t.a;
                E3.b.get();
                Boolean bool2 = (Boolean) G3.g.b();
                bool2.getClass();
                return bool2;
            case 14:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.P.b();
                l.getClass();
                return l;
            case 15:
                List list5 = AbstractC3893t.a;
                O2.b.get();
                Long l2 = (Long) Q2.q0.b();
                l2.getClass();
                return l2;
            case 16:
                List list6 = AbstractC3893t.a;
                B3.b.get();
                Double d = (Double) D3.c.b();
                d.getClass();
                return d;
            default:
                List list7 = AbstractC3893t.a;
                O2.b.get();
                return (String) Q2.t0.b();
        }
    }

    public e(Function2 function2) {
        this.a = 4;
    }
}
