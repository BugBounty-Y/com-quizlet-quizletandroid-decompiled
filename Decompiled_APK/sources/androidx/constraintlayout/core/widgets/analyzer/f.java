package androidx.constraintlayout.core.widgets.analyzer;

import android.app.Application;
import android.app.KeyguardManager;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.os.Process;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.collection.Y;
import androidx.navigation.U;
import com.amazon.device.ads.DtbConstants;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3760x4;
import com.perimeterx.mobile_sdk.doctor_app.ui.PXDoctorActivity;
import com.perimeterx.mobile_sdk.local_data.w;
import com.perimeterx.mobile_sdk.local_data.x;
import com.perimeterx.mobile_sdk.main.PXPolicy;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.collections.G;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class f {
    public static f j;
    public final /* synthetic */ int a;
    public boolean b;
    public boolean c;
    public final Object d;
    public final Object e;
    public final Object f;
    public Serializable g;
    public Object h;
    public Object i;

    public f(String appId, Application application, PXPolicy pXPolicy) throws Throwable {
        this.a = 1;
        this.d = application;
        this.e = pXPolicy;
        this.i = new com.perimeterx.mobile_sdk.doctor_app.model.d();
        this.f = new C1721Kc(application);
        Intrinsics.checkNotNullParameter(appId, "appId");
        com.perimeterx.mobile_sdk.doctor_app.model.c cVar = new com.perimeterx.mobile_sdk.doctor_app.model.c();
        cVar.a = appId;
        this.h = cVar;
        Intrinsics.checkNotNullParameter(appId, "<set-?>");
        cVar.a = appId;
        x key = x.i;
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        com.perimeterx.mobile_sdk.local_data.b bVar = w.c;
        kotlin.coroutines.h hVar = null;
        if (bVar == null) {
            Intrinsics.m("storage");
            throw null;
        }
        if (!Intrinsics.b(bVar.a(key, appId), DtbConstants.APS_ADAPTER_VERSION_2)) {
            x key2 = x.h;
            String appId2 = cVar.a;
            Intrinsics.checkNotNullParameter(key2, "key");
            Intrinsics.checkNotNullParameter(appId2, "appId");
            com.perimeterx.mobile_sdk.local_data.b bVar2 = w.c;
            if (bVar2 == null) {
                Intrinsics.m("storage");
                throw null;
            }
            bVar2.c("", key2, appId2);
            String appId3 = cVar.a;
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(appId3, "appId");
            com.perimeterx.mobile_sdk.local_data.b bVar3 = w.c;
            if (bVar3 == null) {
                Intrinsics.m("storage");
                throw null;
            }
            bVar3.c(DtbConstants.APS_ADAPTER_VERSION_2, key, appId3);
        }
        PXDoctorActivity.h = this;
        com.perimeterx.mobile_sdk.doctor_app.model.d dVar = new com.perimeterx.mobile_sdk.doctor_app.model.d();
        this.i = dVar;
        dVar.c = cVar.c;
        dVar.d = cVar.d;
        boolean z = false;
        cVar.g = false;
        this.g = null;
        dVar.g = null;
        c(new assistantMode.utils.studiableMetadata.b(23));
        Intrinsics.checkNotNullParameter("onCreate", "string");
        Y yF = O.f(new Exception().getStackTrace());
        while (true) {
            if (!yF.hasNext()) {
                break;
            }
            String string = ((StackTraceElement) yF.next()).toString();
            Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
            if (StringsKt.G(string, "onCreate", false)) {
                z = true;
                break;
            }
        }
        ((com.perimeterx.mobile_sdk.doctor_app.model.c) this.h).c = z;
        ((com.perimeterx.mobile_sdk.doctor_app.model.d) this.i).c = z;
        C1721Kc c1721Kc = (C1721Kc) this.f;
        U completion = new U(this, 8);
        c1721Kc.getClass();
        Intrinsics.checkNotNullParameter(completion, "completion");
        if (c1721Kc.b()) {
            completion.invoke(Boolean.TRUE);
        } else {
            E.A(E.c(kotlinx.coroutines.O.a), null, null, new com.perimeterx.mobile_sdk.doctor_app.a(c1721Kc, new com.braze.triggers.managers.h(8, c1721Kc, completion), hVar, 0), 3);
        }
    }

    public void a(com.perimeterx.mobile_sdk.doctor_app.model.a action) {
        Intrinsics.checkNotNullParameter(action, "action");
        d(B.f(action));
    }

    public void b(com.perimeterx.mobile_sdk.doctor_app.state.a aVar) {
        int iOrdinal = aVar.ordinal();
        if (iOrdinal == 0) {
            com.perimeterx.mobile_sdk.doctor_app.e action = PXDoctorActivity.f != null ? com.perimeterx.mobile_sdk.doctor_app.e.c : com.perimeterx.mobile_sdk.doctor_app.e.b;
            Intrinsics.checkNotNullParameter(action, "action");
            int iOrdinal2 = action.ordinal();
            com.perimeterx.mobile_sdk.doctor_app.model.a aVar2 = (iOrdinal2 == 0 || iOrdinal2 == 4) ? null : new com.perimeterx.mobile_sdk.doctor_app.model.a(action);
            Intrinsics.d(aVar2);
            a(aVar2);
            return;
        }
        if (iOrdinal == 1) {
            com.perimeterx.mobile_sdk.doctor_app.model.a action2 = new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.quizlet.shared.usecase.folderstudymaterials.c(22));
            Intrinsics.checkNotNullParameter(action2, "action");
            d(B.f(action2));
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            com.perimeterx.mobile_sdk.doctor_app.e action3 = com.perimeterx.mobile_sdk.doctor_app.e.c;
            Intrinsics.checkNotNullParameter(action3, "action");
            com.perimeterx.mobile_sdk.doctor_app.model.a aVar3 = new com.perimeterx.mobile_sdk.doctor_app.model.a(action3);
            com.perimeterx.mobile_sdk.doctor_app.e action4 = com.perimeterx.mobile_sdk.doctor_app.e.l;
            Intrinsics.checkNotNullParameter(action4, "action");
            d(B.f(aVar3, new com.perimeterx.mobile_sdk.doctor_app.model.a(action4)));
        }
    }

    public void c(com.perimeterx.mobile_sdk.doctor_app.state.d state) throws Throwable {
        int i = 1;
        Iterator it2 = state.d().iterator();
        Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
        while (it2.hasNext()) {
            Object next = it2.next();
            Intrinsics.checkNotNullExpressionValue(next, "next(...)");
            if (com.perimeterx.mobile_sdk.doctor_app.b.a[((com.perimeterx.mobile_sdk.doctor_app.state.e) next).ordinal()] != 1) {
                throw new NoWhenBranchMatchedException();
            }
            if (!((com.perimeterx.mobile_sdk.doctor_app.model.d) this.i).d) {
                return;
            }
        }
        com.perimeterx.mobile_sdk.doctor_app.model.c cVar = (com.perimeterx.mobile_sdk.doctor_app.model.c) this.h;
        cVar.getClass();
        Intrinsics.checkNotNullParameter(state, "<set-?>");
        cVar.b = state;
        u uVar = PXDoctorActivity.e;
        Intrinsics.checkNotNullParameter(state, "state");
        PXDoctorActivity.g = state;
        PXDoctorActivity pXDoctorActivity = PXDoctorActivity.f;
        if (pXDoctorActivity != null) {
            pXDoctorActivity.v();
        }
        com.perimeterx.mobile_sdk.session.l lVar = com.perimeterx.mobile_sdk.session.l.a;
        E.D(kotlin.coroutines.n.a, new com.perimeterx.mobile_sdk.detections.device.touch_interception.d(2, i, null));
    }

    public void d(ArrayList actions) {
        String str;
        String str2;
        Intrinsics.checkNotNullParameter(actions, "actions");
        Iterator it2 = actions.iterator();
        Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            Object next = it2.next();
            Intrinsics.checkNotNullExpressionValue(next, "next(...)");
            if (((com.perimeterx.mobile_sdk.doctor_app.model.a) next).a == com.perimeterx.mobile_sdk.doctor_app.e.c) {
                com.perimeterx.mobile_sdk.doctor_app.e eVar = ((com.perimeterx.mobile_sdk.doctor_app.model.a) CollectionsKt.U(actions)).a;
                com.perimeterx.mobile_sdk.doctor_app.e action = com.perimeterx.mobile_sdk.doctor_app.e.d;
                if (eVar != action) {
                    Intrinsics.checkNotNullParameter(action, "action");
                    actions.add(new com.perimeterx.mobile_sdk.doctor_app.model.a(action));
                    break;
                }
            }
        }
        if (actions.isEmpty()) {
            return;
        }
        com.perimeterx.mobile_sdk.doctor_app.model.a aVar = (com.perimeterx.mobile_sdk.doctor_app.model.a) G.z(actions);
        com.braze.triggers.managers.h hVar = new com.braze.triggers.managers.h(11, this, actions);
        int iOrdinal = aVar.a.ordinal();
        com.perimeterx.mobile_sdk.doctor_app.model.c cVar = (com.perimeterx.mobile_sdk.doctor_app.model.c) this.h;
        switch (iOrdinal) {
            case 0:
                com.perimeterx.mobile_sdk.doctor_app.state.d dVar = aVar.b;
                if (dVar != null) {
                    c(dVar);
                }
                hVar.invoke();
                return;
            case 1:
                l(new com.perimeterx.mobile_sdk.doctor_app.d(hVar, 2));
                return;
            case 2:
                com.perimeterx.mobile_sdk.doctor_app.d dVar2 = new com.perimeterx.mobile_sdk.doctor_app.d(hVar, 1);
                if (!Intrinsics.b(Looper.myLooper(), Looper.getMainLooper())) {
                    new Handler(Looper.getMainLooper()).post(new com.google.firebase.crashlytics.internal.common.i(11, this, dVar2));
                    return;
                }
                PXDoctorActivity pXDoctorActivity = PXDoctorActivity.f;
                if (pXDoctorActivity == null) {
                    dVar2.invoke();
                    return;
                } else {
                    this.b = true;
                    pXDoctorActivity.q(false, new com.braze.triggers.managers.h(10, this, dVar2));
                    return;
                }
            case 3:
                PXDoctorActivity pXDoctorActivity2 = PXDoctorActivity.f;
                if (pXDoctorActivity2 != null) {
                    pXDoctorActivity2.finish();
                }
                hVar.invoke();
                return;
            case 4:
                com.perimeterx.mobile_sdk.doctor_app.ui.i popupType = aVar.c;
                if (popupType == null) {
                    hVar.invoke();
                    return;
                }
                com.perimeterx.mobile_sdk.doctor_app.d dVar3 = new com.perimeterx.mobile_sdk.doctor_app.d(hVar, 0);
                PXDoctorActivity pXDoctorActivity3 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity3);
                Intrinsics.checkNotNullParameter(popupType, "popupType");
                PXDoctorActivity.j = dVar3;
                int iOrdinal2 = popupType.ordinal();
                if (iOrdinal2 == 0) {
                    str = "Native framework test";
                } else {
                    if (iOrdinal2 != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    str = "Web view framework test";
                }
                int iOrdinal3 = popupType.ordinal();
                if (iOrdinal3 == 0) {
                    str2 = "Start navigating your native app screens";
                } else {
                    if (iOrdinal3 != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    str2 = "Start navigating your web view pages";
                }
                View viewFindViewById = pXDoctorActivity3.findViewById(R.id.doctor_popup_view);
                ImageView imageView = (ImageView) pXDoctorActivity3.findViewById(R.id.doctor_popup_thumbnail_image_view);
                TextView textView = (TextView) pXDoctorActivity3.findViewById(R.id.doctor_popup_title_text_view);
                TextView textView2 = (TextView) pXDoctorActivity3.findViewById(R.id.doctor_popup_message_text_view);
                viewFindViewById.setVisibility(0);
                imageView.setVisibility(0);
                textView.setVisibility(0);
                textView2.setVisibility(0);
                textView.setText(str);
                textView2.setText(str2);
                pXDoctorActivity3.r(true, new com.braze.ui.inappmessage.listeners.a(26));
                return;
            case 5:
                com.perimeterx.mobile_sdk.doctor_app.model.d dVar4 = (com.perimeterx.mobile_sdk.doctor_app.model.d) this.i;
                com.perimeterx.mobile_sdk.doctor_app.model.b bVar = new com.perimeterx.mobile_sdk.doctor_app.model.b();
                dVar4.e = bVar;
                bVar.g = cVar.e;
                bVar.h = cVar.f;
                bVar.j = com.perimeterx.mobile_sdk.doctor_app.model.c.h;
                hVar.invoke();
                return;
            case 6:
                ((com.perimeterx.mobile_sdk.doctor_app.model.d) this.i).f = new com.perimeterx.mobile_sdk.doctor_app.model.i();
                hVar.invoke();
                return;
            case 7:
                ((com.perimeterx.mobile_sdk.doctor_app.model.d) this.i).b = new Date();
                String string = ((com.perimeterx.mobile_sdk.doctor_app.model.d) this.i).a().toString();
                x key = x.h;
                String appId = cVar.a;
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(appId, "appId");
                com.perimeterx.mobile_sdk.local_data.b bVar2 = w.c;
                if (bVar2 == null) {
                    Intrinsics.m("storage");
                    throw null;
                }
                if (string == null) {
                    string = "";
                }
                bVar2.c(string, key, appId);
                hVar.invoke();
                return;
            case 8:
                com.perimeterx.mobile_sdk.doctor_app.model.d dVarO = o();
                if (dVarO != null) {
                    this.i = dVarO;
                    this.g = dVarO.g;
                }
                hVar.invoke();
                return;
            case 9:
                cVar.g = true;
                hVar.invoke();
                return;
            case 10:
                com.perimeterx.mobile_sdk.doctor_app.model.d dVar5 = new com.perimeterx.mobile_sdk.doctor_app.model.d();
                this.i = dVar5;
                dVar5.c = cVar.c;
                dVar5.d = cVar.d;
                cVar.g = false;
                this.g = null;
                dVar5.g = null;
                c(new assistantMode.utils.studiableMetadata.b(23));
                hVar.invoke();
                return;
            case 11:
                Process.killProcess(Process.myPid());
                return;
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    public void e(Function0 function0) {
        if (PXDoctorActivity.f != null) {
            if (function0 != null) {
                function0.invoke();
                return;
            }
            return;
        }
        PXDoctorActivity.i = new com.braze.triggers.managers.h(9, this, function0);
        Application application = (Application) this.d;
        Intent intent = new Intent(application, (Class<?>) PXDoctorActivity.class);
        intent.setFlags(268435456);
        application.startActivity(intent);
        this.b = true;
        this.c = false;
    }

    public boolean f() {
        com.perimeterx.mobile_sdk.doctor_app.state.d dVarA = ((com.perimeterx.mobile_sdk.doctor_app.model.c) this.h).a();
        return (dVarA instanceof com.perimeterx.mobile_sdk.doctor_app.state.c ? (com.perimeterx.mobile_sdk.doctor_app.state.c) dVarA : null) != null;
    }

    public void g(g gVar, int i, ArrayList arrayList, m mVar) {
        p pVar = gVar.d;
        if (pVar.c == null) {
            androidx.constraintlayout.core.widgets.f fVar = (androidx.constraintlayout.core.widgets.f) this.d;
            if (pVar == fVar.d || pVar == fVar.e) {
                return;
            }
            if (mVar == null) {
                mVar = new m();
                mVar.a = null;
                mVar.b = new ArrayList();
                mVar.a = pVar;
                arrayList.add(mVar);
            }
            pVar.c = mVar;
            mVar.b.add(pVar);
            g gVar2 = pVar.h;
            Iterator it2 = gVar2.k.iterator();
            while (it2.hasNext()) {
                e eVar = (e) it2.next();
                if (eVar instanceof g) {
                    g((g) eVar, i, arrayList, mVar);
                }
            }
            g gVar3 = pVar.i;
            Iterator it3 = gVar3.k.iterator();
            while (it3.hasNext()) {
                e eVar2 = (e) it3.next();
                if (eVar2 instanceof g) {
                    g((g) eVar2, i, arrayList, mVar);
                }
            }
            if (i == 1 && (pVar instanceof n)) {
                Iterator it4 = ((n) pVar).k.k.iterator();
                while (it4.hasNext()) {
                    e eVar3 = (e) it4.next();
                    if (eVar3 instanceof g) {
                        g((g) eVar3, i, arrayList, mVar);
                    }
                }
            }
            Iterator it5 = gVar2.l.iterator();
            while (it5.hasNext()) {
                g((g) it5.next(), i, arrayList, mVar);
            }
            Iterator it6 = gVar3.l.iterator();
            while (it6.hasNext()) {
                g((g) it6.next(), i, arrayList, mVar);
            }
            if (i == 1 && (pVar instanceof n)) {
                Iterator it7 = ((n) pVar).k.l.iterator();
                while (it7.hasNext()) {
                    g((g) it7.next(), i, arrayList, mVar);
                }
            }
        }
    }

    public boolean h() {
        com.perimeterx.mobile_sdk.doctor_app.state.d dVarA = ((com.perimeterx.mobile_sdk.doctor_app.model.c) this.h).a();
        return (dVarA instanceof com.perimeterx.mobile_sdk.doctor_app.state.h ? (com.perimeterx.mobile_sdk.doctor_app.state.h) dVarA : null) != null;
    }

    public void i(androidx.constraintlayout.core.widgets.f fVar) {
        androidx.constraintlayout.core.widgets.d dVar;
        androidx.constraintlayout.core.widgets.d dVar2;
        float f;
        androidx.constraintlayout.core.widgets.d dVar3;
        androidx.constraintlayout.core.widgets.d dVar4;
        androidx.constraintlayout.core.widgets.d dVar5;
        androidx.constraintlayout.core.widgets.d dVar6;
        Iterator it2 = fVar.t0.iterator();
        while (it2.hasNext()) {
            androidx.constraintlayout.core.widgets.e eVar = (androidx.constraintlayout.core.widgets.e) it2.next();
            androidx.constraintlayout.core.widgets.d[] dVarArr = eVar.V;
            androidx.constraintlayout.core.widgets.d dVar7 = dVarArr[0];
            androidx.constraintlayout.core.widgets.d dVar8 = dVarArr[1];
            if (eVar.j0 == 8) {
                eVar.a = true;
            } else {
                float f2 = eVar.x;
                androidx.constraintlayout.core.widgets.d dVar9 = androidx.constraintlayout.core.widgets.d.c;
                if (f2 < 1.0f && dVar7 == dVar9) {
                    eVar.s = 2;
                }
                float f3 = eVar.A;
                if (f3 < 1.0f && dVar8 == dVar9) {
                    eVar.t = 2;
                }
                float f4 = eVar.Z;
                androidx.constraintlayout.core.widgets.d dVar10 = androidx.constraintlayout.core.widgets.d.b;
                androidx.constraintlayout.core.widgets.d dVar11 = androidx.constraintlayout.core.widgets.d.a;
                if (f4 > DefinitionKt.NO_Float_VALUE) {
                    if (dVar7 == dVar9 && (dVar8 == dVar10 || dVar8 == dVar11)) {
                        eVar.s = 3;
                    } else if (dVar8 == dVar9 && (dVar7 == dVar10 || dVar7 == dVar11)) {
                        eVar.t = 3;
                    } else if (dVar7 == dVar9 && dVar8 == dVar9) {
                        if (eVar.s == 0) {
                            eVar.s = 3;
                        }
                        if (eVar.t == 0) {
                            eVar.t = 3;
                        }
                    }
                }
                androidx.constraintlayout.core.widgets.c cVar = eVar.M;
                androidx.constraintlayout.core.widgets.c cVar2 = eVar.K;
                if (dVar7 == dVar9 && eVar.s == 1 && (cVar2.f == null || cVar.f == null)) {
                    dVar7 = dVar10;
                }
                androidx.constraintlayout.core.widgets.c cVar3 = eVar.N;
                androidx.constraintlayout.core.widgets.c cVar4 = eVar.L;
                if (dVar8 == dVar9 && eVar.t == 1 && (cVar4.f == null || cVar3.f == null)) {
                    dVar8 = dVar10;
                }
                l lVar = eVar.d;
                lVar.d = dVar7;
                int i = eVar.s;
                lVar.a = i;
                n nVar = eVar.e;
                nVar.d = dVar8;
                Iterator it3 = it2;
                int i2 = eVar.t;
                nVar.a = i2;
                androidx.constraintlayout.core.widgets.d dVar12 = androidx.constraintlayout.core.widgets.d.d;
                if ((dVar7 == dVar12 || dVar7 == dVar11 || dVar7 == dVar10) && (dVar8 == dVar12 || dVar8 == dVar11 || dVar8 == dVar10)) {
                    androidx.constraintlayout.core.widgets.d dVar13 = dVar8;
                    int iR = eVar.r();
                    if (dVar7 == dVar12) {
                        iR = (fVar.r() - cVar2.g) - cVar.g;
                        dVar7 = dVar11;
                    }
                    int i3 = iR;
                    int iL = eVar.l();
                    if (dVar13 == dVar12) {
                        iL = (fVar.l() - cVar4.g) - cVar3.g;
                        dVar13 = dVar11;
                    }
                    t(eVar, dVar7, i3, dVar13, iL);
                    eVar.d.e.d(eVar.r());
                    eVar.e.e.d(eVar.l());
                    eVar.a = true;
                } else {
                    androidx.constraintlayout.core.widgets.c[] cVarArr = eVar.S;
                    if (dVar7 != dVar9 || (dVar8 != dVar10 && dVar8 != dVar11)) {
                        dVar = dVar7;
                        dVar2 = dVar10;
                        f = f3;
                        dVar3 = dVar11;
                        dVar4 = dVar8;
                    } else if (i == 3) {
                        if (dVar8 == dVar10) {
                            t(eVar, dVar10, 0, dVar10, 0);
                        }
                        int iL2 = eVar.l();
                        t(eVar, dVar11, (int) ((iL2 * eVar.Z) + 0.5f), dVar11, iL2);
                        eVar.d.e.d(eVar.r());
                        eVar.e.e.d(eVar.l());
                        eVar.a = true;
                    } else {
                        dVar = dVar7;
                        dVar2 = dVar10;
                        dVar3 = dVar11;
                        if (i == 1) {
                            t(eVar, dVar2, 0, dVar8, 0);
                            eVar.d.e.m = eVar.r();
                        } else {
                            f = f3;
                            dVar4 = dVar8;
                            if (i == 2) {
                                androidx.constraintlayout.core.widgets.d dVar14 = fVar.V[0];
                                if (dVar14 == dVar3 || dVar14 == dVar12) {
                                    t(eVar, dVar3, (int) ((f2 * fVar.r()) + 0.5f), dVar4, eVar.l());
                                    eVar.d.e.d(eVar.r());
                                    eVar.e.e.d(eVar.l());
                                    eVar.a = true;
                                }
                            } else if (cVarArr[0].f == null || cVarArr[1].f == null) {
                                t(eVar, dVar2, 0, dVar4, 0);
                                eVar.d.e.d(eVar.r());
                                eVar.e.e.d(eVar.l());
                                eVar.a = true;
                            }
                        }
                    }
                    if (dVar4 != dVar9 || (dVar != dVar2 && dVar != dVar3)) {
                        androidx.constraintlayout.core.widgets.d dVar15 = dVar;
                        dVar5 = dVar2;
                        dVar6 = dVar15;
                    } else if (i2 == 3) {
                        if (dVar == dVar2) {
                            t(eVar, dVar2, 0, dVar2, 0);
                        }
                        int iR2 = eVar.r();
                        float f5 = eVar.Z;
                        if (eVar.a0 == -1) {
                            f5 = 1.0f / f5;
                        }
                        t(eVar, dVar3, iR2, dVar3, (int) ((iR2 * f5) + 0.5f));
                        eVar.d.e.d(eVar.r());
                        eVar.e.e.d(eVar.l());
                        eVar.a = true;
                    } else if (i2 == 1) {
                        t(eVar, dVar, 0, dVar2, 0);
                        eVar.e.e.m = eVar.l();
                    } else {
                        androidx.constraintlayout.core.widgets.d dVar16 = dVar;
                        dVar5 = dVar2;
                        if (i2 == 2) {
                            androidx.constraintlayout.core.widgets.d dVar17 = fVar.V[1];
                            if (dVar17 == dVar3 || dVar17 == dVar12) {
                                t(eVar, dVar16, eVar.r(), dVar3, (int) ((f * fVar.l()) + 0.5f));
                                eVar.d.e.d(eVar.r());
                                eVar.e.e.d(eVar.l());
                                eVar.a = true;
                            } else {
                                dVar6 = dVar16;
                            }
                        } else {
                            dVar6 = dVar16;
                            if (cVarArr[2].f == null || cVarArr[3].f == null) {
                                t(eVar, dVar5, 0, dVar4, 0);
                                eVar.d.e.d(eVar.r());
                                eVar.e.e.d(eVar.l());
                                eVar.a = true;
                            }
                        }
                    }
                    if (dVar6 == dVar9 && dVar4 == dVar9) {
                        if (i == 1 || i2 == 1) {
                            t(eVar, dVar5, 0, dVar5, 0);
                            eVar.d.e.m = eVar.r();
                            eVar.e.e.m = eVar.l();
                        } else if (i2 == 2 && i == 2) {
                            androidx.constraintlayout.core.widgets.d[] dVarArr2 = fVar.V;
                            if (dVarArr2[0] == dVar3 && dVarArr2[1] == dVar3) {
                                t(eVar, dVar3, (int) ((f2 * fVar.r()) + 0.5f), dVar3, (int) ((f * fVar.l()) + 0.5f));
                                eVar.d.e.d(eVar.r());
                                eVar.e.e.d(eVar.l());
                                eVar.a = true;
                            }
                        }
                    }
                }
                it2 = it3;
            }
        }
    }

    public void j() {
        ArrayList arrayList = (ArrayList) this.f;
        arrayList.clear();
        androidx.constraintlayout.core.widgets.f fVar = (androidx.constraintlayout.core.widgets.f) this.e;
        fVar.d.f();
        fVar.e.f();
        arrayList.add(fVar.d);
        arrayList.add(fVar.e);
        Iterator it2 = fVar.t0.iterator();
        HashSet hashSet = null;
        while (it2.hasNext()) {
            androidx.constraintlayout.core.widgets.e eVar = (androidx.constraintlayout.core.widgets.e) it2.next();
            if (eVar instanceof androidx.constraintlayout.core.widgets.i) {
                j jVar = new j(eVar);
                eVar.d.f();
                eVar.e.f();
                jVar.f = ((androidx.constraintlayout.core.widgets.i) eVar).x0;
                arrayList.add(jVar);
            } else {
                if (eVar.y()) {
                    if (eVar.b == null) {
                        eVar.b = new d(eVar, 0);
                    }
                    if (hashSet == null) {
                        hashSet = new HashSet();
                    }
                    hashSet.add(eVar.b);
                } else {
                    arrayList.add(eVar.d);
                }
                if (eVar.z()) {
                    if (eVar.c == null) {
                        eVar.c = new d(eVar, 1);
                    }
                    if (hashSet == null) {
                        hashSet = new HashSet();
                    }
                    hashSet.add(eVar.c);
                } else {
                    arrayList.add(eVar.e);
                }
                if (eVar instanceof androidx.constraintlayout.core.widgets.j) {
                    arrayList.add(new k(eVar));
                }
            }
        }
        if (hashSet != null) {
            arrayList.addAll(hashSet);
        }
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            ((p) it3.next()).f();
        }
        Iterator it4 = arrayList.iterator();
        while (it4.hasNext()) {
            p pVar = (p) it4.next();
            if (pVar.b != fVar) {
                pVar.d();
            }
        }
        ArrayList arrayList2 = (ArrayList) this.g;
        arrayList2.clear();
        androidx.constraintlayout.core.widgets.f fVar2 = (androidx.constraintlayout.core.widgets.f) this.d;
        p(fVar2.d, 0, arrayList2);
        p(fVar2.e, 1, arrayList2);
        this.b = false;
    }

    public void k() {
        com.perimeterx.mobile_sdk.doctor_app.e action = com.perimeterx.mobile_sdk.doctor_app.e.j;
        Intrinsics.checkNotNullParameter(action, "action");
        a(new com.perimeterx.mobile_sdk.doctor_app.model.a(action));
        PXDoctorActivity pXDoctorActivity = PXDoctorActivity.f;
        if (pXDoctorActivity != null) {
            Intent intent = new Intent();
            intent.setAction("android.intent.action.SEND");
            intent.putExtra("android.intent.extra.TEXT", ((com.perimeterx.mobile_sdk.doctor_app.model.d) this.i).a().toString());
            intent.setType("text/plain");
            pXDoctorActivity.startActivity(Intent.createChooser(intent, null));
        }
    }

    public void l(Function0 function0) {
        if (Intrinsics.b(Looper.myLooper(), Looper.getMainLooper())) {
            e(function0);
        } else {
            new Handler(Looper.getMainLooper()).post(new com.google.firebase.crashlytics.internal.common.i(12, this, function0));
        }
    }

    public int m(androidx.constraintlayout.core.widgets.f fVar, int i) {
        ArrayList arrayList;
        int i2;
        int i3;
        long jMax;
        float f;
        androidx.constraintlayout.core.widgets.f fVar2 = fVar;
        ArrayList arrayList2 = (ArrayList) this.g;
        int size = arrayList2.size();
        int i4 = 0;
        long jMax2 = 0;
        while (i4 < size) {
            p pVar = ((m) arrayList2.get(i4)).a;
            if (!(pVar instanceof d) ? !(i != 0 ? (pVar instanceof n) : (pVar instanceof l)) : ((d) pVar).f != i) {
                g gVar = (i == 0 ? fVar2.d : fVar2.e).h;
                g gVar2 = (i == 0 ? fVar2.d : fVar2.e).i;
                boolean zContains = pVar.h.l.contains(gVar);
                g gVar3 = pVar.i;
                boolean zContains2 = gVar3.l.contains(gVar2);
                long j2 = pVar.j();
                g gVar4 = pVar.h;
                if (zContains && zContains2) {
                    long jB = m.b(gVar4, 0L);
                    ArrayList arrayList3 = arrayList2;
                    i2 = size;
                    long jA = m.a(gVar3, 0L);
                    long j3 = jB - j2;
                    int i5 = gVar3.f;
                    arrayList = arrayList3;
                    i3 = i4;
                    if (j3 >= (-i5)) {
                        j3 += i5;
                    }
                    long j4 = (-jA) - j2;
                    long j5 = gVar4.f;
                    long j6 = j4 - j5;
                    if (j6 >= j5) {
                        j6 -= j5;
                    }
                    androidx.constraintlayout.core.widgets.e eVar = pVar.b;
                    if (i == 0) {
                        f = eVar.g0;
                    } else if (i == 1) {
                        f = eVar.h0;
                    } else {
                        eVar.getClass();
                        f = -1.0f;
                    }
                    float f2 = f > DefinitionKt.NO_Float_VALUE ? (long) ((j3 / (1.0f - f)) + (j6 / f)) : 0L;
                    jMax = (gVar4.f + ((((long) ((f2 * f) + 0.5f)) + j2) + ((long) android.support.v4.media.session.a.a(1.0f, f, f2, 0.5f)))) - gVar3.f;
                } else {
                    arrayList = arrayList2;
                    i2 = size;
                    i3 = i4;
                    jMax = zContains ? Math.max(m.b(gVar4, gVar4.f), gVar4.f + j2) : zContains2 ? Math.max(-m.a(gVar3, gVar3.f), (-gVar3.f) + j2) : (pVar.j() + gVar4.f) - gVar3.f;
                }
            } else {
                arrayList = arrayList2;
                i2 = size;
                i3 = i4;
                jMax = 0;
            }
            jMax2 = Math.max(jMax2, jMax);
            i4 = i3 + 1;
            fVar2 = fVar;
            size = i2;
            arrayList2 = arrayList;
        }
        return (int) jMax2;
    }

    public void n() {
        com.perimeterx.mobile_sdk.doctor_app.e action = com.perimeterx.mobile_sdk.doctor_app.e.i;
        Intrinsics.checkNotNullParameter(action, "action");
        d(B.f(new com.perimeterx.mobile_sdk.doctor_app.model.a(action), new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.quizlet.shared.usecase.studiableMetadata.a(22))));
    }

    public com.perimeterx.mobile_sdk.doctor_app.model.d o() {
        x key = x.h;
        String appId = ((com.perimeterx.mobile_sdk.doctor_app.model.c) this.h).a;
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(appId, "appId");
        com.perimeterx.mobile_sdk.local_data.b bVar = w.c;
        if (bVar == null) {
            Intrinsics.m("storage");
            throw null;
        }
        String strA = bVar.a(key, appId);
        if (strA != null && strA.length() > 0) {
            try {
                JSONObject jSONObject = new JSONObject(strA);
                SimpleDateFormat simpleDateFormat = com.perimeterx.mobile_sdk.doctor_app.model.d.h;
                return AbstractC3760x4.a(jSONObject);
            } catch (Exception unused) {
            }
        }
        return null;
    }

    public void p(p pVar, int i, ArrayList arrayList) {
        g gVar;
        Iterator it2 = pVar.h.k.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            gVar = pVar.i;
            if (!zHasNext) {
                break;
            }
            e eVar = (e) it2.next();
            if (eVar instanceof g) {
                g((g) eVar, i, arrayList, null);
            } else if (eVar instanceof p) {
                g(((p) eVar).h, i, arrayList, null);
            }
        }
        Iterator it3 = gVar.k.iterator();
        while (it3.hasNext()) {
            e eVar2 = (e) it3.next();
            if (eVar2 instanceof g) {
                g((g) eVar2, i, arrayList, null);
            } else if (eVar2 instanceof p) {
                g(((p) eVar2).i, i, arrayList, null);
            }
        }
        if (i == 1) {
            Iterator it4 = ((n) pVar).k.k.iterator();
            while (it4.hasNext()) {
                e eVar3 = (e) it4.next();
                if (eVar3 instanceof g) {
                    g((g) eVar3, i, arrayList, null);
                }
            }
        }
    }

    public void q() {
        if (f() && ((com.perimeterx.mobile_sdk.doctor_app.f) this.g) == com.perimeterx.mobile_sdk.doctor_app.f.c) {
            com.perimeterx.mobile_sdk.doctor_app.model.b bVar = ((com.perimeterx.mobile_sdk.doctor_app.model.d) this.i).e;
            if (bVar != null) {
                bVar.i = true;
            }
            new Handler(Looper.getMainLooper()).post(new com.perimeterx.mobile_sdk.doctor_app.c(this, 4));
        }
    }

    public void r() {
        if (((com.perimeterx.mobile_sdk.doctor_app.f) this.g) == com.perimeterx.mobile_sdk.doctor_app.f.c && h()) {
            com.perimeterx.mobile_sdk.doctor_app.model.i iVar = ((com.perimeterx.mobile_sdk.doctor_app.model.d) this.i).f;
            if (iVar != null) {
                iVar.d = true;
            }
            new Handler(Looper.getMainLooper()).post(new com.perimeterx.mobile_sdk.doctor_app.c(this, 6));
        }
    }

    public void s() {
        Application context = (Application) this.d;
        Intrinsics.checkNotNullParameter(context, "context");
        Object systemService = context.getSystemService("keyguard");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.app.KeyguardManager");
        KeyguardManager keyguardManager = (KeyguardManager) systemService;
        Object systemService2 = context.getSystemService("power");
        Intrinsics.e(systemService2, "null cannot be cast to non-null type android.os.PowerManager");
        if (!((PowerManager) systemService2).isInteractive() || keyguardManager.isKeyguardLocked()) {
            return;
        }
        PXDoctorActivity pXDoctorActivity = PXDoctorActivity.f;
        if (pXDoctorActivity != null) {
            pXDoctorActivity.finish();
        }
        new Handler(Looper.getMainLooper()).postDelayed(new com.perimeterx.mobile_sdk.doctor_app.c(this, 0), 1000L);
    }

    public void t(androidx.constraintlayout.core.widgets.e eVar, androidx.constraintlayout.core.widgets.d dVar, int i, androidx.constraintlayout.core.widgets.d dVar2, int i2) {
        b bVar = (b) this.i;
        bVar.a = dVar;
        bVar.b = dVar2;
        bVar.c = i;
        bVar.d = i2;
        ((c) this.h).b(eVar, bVar);
        eVar.S(bVar.e);
        eVar.N(bVar.f);
        eVar.F = bVar.h;
        eVar.J(bVar.g);
    }

    public String toString() {
        switch (this.a) {
            case 2:
                ArrayList arrayList = new ArrayList();
                if (this.b) {
                    arrayList.add("isRegularFile");
                }
                if (this.c) {
                    arrayList.add("isDirectory");
                }
                Long l = (Long) this.e;
                if (l != null) {
                    arrayList.add("byteCount=" + l);
                }
                Long l2 = (Long) this.f;
                if (l2 != null) {
                    arrayList.add("createdAt=" + l2);
                }
                Long l3 = (Long) this.g;
                if (l3 != null) {
                    arrayList.add("lastModifiedAt=" + l3);
                }
                Long l4 = (Long) this.h;
                if (l4 != null) {
                    arrayList.add("lastAccessedAt=" + l4);
                }
                Map map = (Map) this.i;
                if (!map.isEmpty()) {
                    arrayList.add("extras=" + map);
                }
                return CollectionsKt.S(arrayList, ", ", "FileMetadata(", ")", null, 56);
            default:
                return super.toString();
        }
    }

    public void u() {
        a aVar;
        Iterator it2 = ((androidx.constraintlayout.core.widgets.f) this.d).t0.iterator();
        while (it2.hasNext()) {
            androidx.constraintlayout.core.widgets.e eVar = (androidx.constraintlayout.core.widgets.e) it2.next();
            if (!eVar.a) {
                androidx.constraintlayout.core.widgets.d[] dVarArr = eVar.V;
                boolean z = false;
                androidx.constraintlayout.core.widgets.d dVar = dVarArr[0];
                androidx.constraintlayout.core.widgets.d dVar2 = dVarArr[1];
                int i = eVar.s;
                int i2 = eVar.t;
                androidx.constraintlayout.core.widgets.d dVar3 = androidx.constraintlayout.core.widgets.d.b;
                androidx.constraintlayout.core.widgets.d dVar4 = androidx.constraintlayout.core.widgets.d.c;
                boolean z2 = dVar == dVar3 || (dVar == dVar4 && i == 1);
                if (dVar2 == dVar3 || (dVar2 == dVar4 && i2 == 1)) {
                    z = true;
                }
                h hVar = eVar.d.e;
                boolean z3 = hVar.j;
                h hVar2 = eVar.e.e;
                boolean z4 = hVar2.j;
                boolean z5 = z2;
                androidx.constraintlayout.core.widgets.d dVar5 = androidx.constraintlayout.core.widgets.d.a;
                if (z3 && z4) {
                    t(eVar, dVar5, hVar.g, dVar5, hVar2.g);
                    eVar.a = true;
                } else if (z3 && z) {
                    t(eVar, dVar5, hVar.g, dVar3, hVar2.g);
                    if (dVar2 == dVar4) {
                        eVar.e.e.m = eVar.l();
                    } else {
                        eVar.e.e.d(eVar.l());
                        eVar.a = true;
                    }
                } else if (z4 && z5) {
                    t(eVar, dVar3, hVar.g, dVar5, hVar2.g);
                    if (dVar == dVar4) {
                        eVar.d.e.m = eVar.r();
                    } else {
                        eVar.d.e.d(eVar.r());
                        eVar.a = true;
                    }
                }
                if (eVar.a && (aVar = eVar.e.l) != null) {
                    aVar.d(eVar.d0);
                }
            }
        }
    }

    public f(androidx.constraintlayout.core.widgets.f fVar) {
        this.a = 0;
        this.b = true;
        this.c = true;
        this.f = new ArrayList();
        new ArrayList();
        this.h = null;
        this.i = new b();
        this.g = new ArrayList();
        this.d = fVar;
        this.e = fVar;
    }

    public f(boolean z, boolean z2, okio.x xVar, Long l, Long l2, Long l3, Long l4, Map extras) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(extras, "extras");
        this.b = z;
        this.c = z2;
        this.d = xVar;
        this.e = l;
        this.f = l2;
        this.g = l3;
        this.h = l4;
        this.i = V.l(extras);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ f(boolean z, boolean z2, okio.x xVar, Long l, Long l2, Long l3, Long l4) {
        this(z, z2, xVar, l, l2, l3, l4, V.c());
        this.a = 2;
    }
}
