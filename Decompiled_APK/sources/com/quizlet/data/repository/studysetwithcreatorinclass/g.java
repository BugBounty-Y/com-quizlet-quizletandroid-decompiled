package com.quizlet.data.repository.studysetwithcreatorinclass;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.webkit.WebView;
import androidx.activity.C0034f;
import androidx.camera.core.internal.CameraUseCaseAdapter$CameraException;
import androidx.compose.runtime.internal.m;
import androidx.lifecycle.B;
import androidx.lifecycle.J;
import androidx.lifecycle.L;
import androidx.recyclerview.widget.C1372j;
import androidx.transition.C1412o;
import androidx.webkit.i;
import com.android.billingclient.api.h;
import com.google.android.gms.ads.internal.j;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.A7;
import com.google.android.gms.internal.ads.AbstractC1972di;
import com.google.android.gms.internal.ads.AbstractC2025es;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.Bs;
import com.google.android.gms.internal.ads.C1804Yb;
import com.google.android.gms.internal.ads.C1807Ye;
import com.google.android.gms.internal.ads.C1813Ze;
import com.google.android.gms.internal.ads.C1849aq;
import com.google.android.gms.internal.ads.C2149hk;
import com.google.android.gms.internal.ads.C2210j2;
import com.google.android.gms.internal.ads.C2313ld;
import com.google.android.gms.internal.ads.C2326lq;
import com.google.android.gms.internal.ads.C2752vn;
import com.google.android.gms.internal.ads.C2881yn;
import com.google.android.gms.internal.ads.Gr;
import com.google.android.gms.internal.ads.Hr;
import com.google.android.gms.internal.ads.Ir;
import com.google.android.gms.internal.ads.Kr;
import com.google.android.gms.internal.ads.Lr;
import com.google.android.gms.internal.ads.Mr;
import com.google.android.gms.internal.ads.Os;
import com.google.android.gms.internal.ads.S4;
import com.google.android.gms.internal.ads.Ts;
import com.google.android.gms.internal.ads.Tv;
import com.google.android.gms.internal.ads.Ur;
import com.google.android.gms.internal.ads.Vp;
import com.google.android.gms.internal.ads.Vr;
import com.google.android.gms.internal.ads.W7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3379p2;
import com.quizlet.data.model.C4115c0;
import com.quizlet.data.model.CreatedFolder;
import com.quizlet.data.model.CreatedFolderWithCreator;
import com.quizlet.data.model.ExerciseDetails;
import com.quizlet.data.model.M1;
import com.quizlet.data.model.NotesToValueInfo;
import com.quizlet.data.model.Question;
import com.quizlet.data.model.StudyMaterialItem$ExplanationQuestionItem;
import com.quizlet.data.model.StudyMaterialItem$FlashcardSetItem;
import com.quizlet.data.model.StudyMaterialItem$FolderItem;
import com.quizlet.data.model.StudyMaterialItem$NoteItem;
import com.quizlet.data.model.StudyMaterialItem$TextbookExerciseItem;
import com.quizlet.data.model.StudyMaterialItem$TextbookItem;
import com.quizlet.data.model.StudySet;
import com.quizlet.data.model.StudySetWithCreator;
import com.quizlet.data.model.Textbook;
import com.quizlet.data.model.User;
import com.quizlet.data.repository.studysetwithcreatorinclass.g;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.edgy.model.AllCountries;
import com.quizlet.edgy.model.AllStates;
import com.quizlet.quizletandroid.k;
import com.quizlet.remote.model.explanations.exercise.RemoteExerciseDetails;
import com.quizlet.remote.model.explanations.question.RemoteQuestion;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.notes.RemoteStudyNote;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.D;
import io.reactivex.rxjava3.core.p;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.A;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.text.Regex;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.X;
import kotlinx.coroutines.flow.s0;
import okhttp3.C;
import okhttp3.C5083l;
import okhttp3.F;
import okhttp3.n;
import okhttp3.r;
import okhttp3.s;
import okhttp3.w;
import okhttp3.y;
import org.chromium.support_lib_boundary.WebViewProviderBoundaryInterface;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class g implements com.google.android.gms.ads.internal.d, com.quizlet.remote.mapper.base.a {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;

    public g(Context context, com.google.android.gms.ads.internal.c cVar, VersionInfoParcel versionInfoParcel) {
        this.a = 4;
        this.b = new Object();
        this.c = context.getApplicationContext();
        this.f = versionInfoParcel;
        this.e = cVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static void A(g gVar, String str) {
        Ir ir = Ir.DEFINED_BY_JAVASCRIPT;
        Kr kr = Kr.DEFINED_BY_JAVASCRIPT;
        Mr mr = Mr.JAVASCRIPT;
        Hr hr = new Hr(Bs.a(ir, kr, mr, mr, false), new C2210j2((A7) gVar.b, (WebView) gVar.c, null, null, Gr.HTML), str);
        ((HashMap) gVar.e).put(str, hr);
        m mVar = (m) gVar.d;
        hr.b(mVar == null ? null : (View) mVar.get());
        Iterator it2 = ((Vr) gVar.f).a.iterator();
        while (it2.hasNext()) {
            Ur ur = (Ur) it2.next();
            View view = (View) ur.a.get();
            if (!hr.f) {
                hr.b.a(view, ur.c);
            }
        }
        hr.c();
    }

    public static JSONObject z(Context context, VersionInfoParcel versionInfoParcel) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            if (((Boolean) W7.b.o()).booleanValue()) {
                jSONObject.put("package_name", context.getPackageName());
            }
            jSONObject.put("js", versionInfoParcel.a);
            jSONObject.put("mf", W7.c.o());
            jSONObject.put("cl", "756340629");
            jSONObject.put("rapid_rc", "dev");
            jSONObject.put("rapid_rollup", "HEAD");
            jSONObject.put("admob_module_version", 12451000);
            jSONObject.put("dynamite_local_version", ModuleDescriptor.MODULE_VERSION);
            jSONObject.put("dynamite_version", com.google.android.gms.dynamite.c.d(context, ModuleDescriptor.MODULE_ID, false));
            jSONObject.put("container_version", 12451000);
        } catch (JSONException unused) {
        }
        return jSONObject;
    }

    @Override // com.google.android.gms.ads.internal.d
    public void a() {
    }

    public void b(androidx.camera.lifecycle.b bVar, K k, List list, androidx.camera.camera2.internal.concurrent.a aVar) {
        J j;
        synchronized (this.b) {
            try {
                AbstractC3242q6.d(!list.isEmpty());
                this.f = aVar;
                synchronized (bVar.a) {
                    j = bVar.b;
                }
                androidx.camera.lifecycle.c cVarK = k(j);
                if (cVarK == null) {
                    return;
                }
                Set set = (Set) ((HashMap) this.d).get(cVarK);
                androidx.camera.camera2.internal.concurrent.a aVar2 = (androidx.camera.camera2.internal.concurrent.a) this.f;
                if (aVar2 == null || aVar2.b != 2) {
                    Iterator it2 = set.iterator();
                    while (it2.hasNext()) {
                        androidx.camera.lifecycle.b bVar2 = (androidx.camera.lifecycle.b) ((HashMap) this.c).get((androidx.camera.lifecycle.a) it2.next());
                        bVar2.getClass();
                        if (!bVar2.equals(bVar) && !bVar2.c().isEmpty()) {
                            throw new IllegalArgumentException("Multiple LifecycleCameras with use cases are registered to the same LifecycleOwner.");
                        }
                    }
                }
                try {
                    synchronized (bVar.c.k) {
                    }
                    androidx.camera.core.internal.g gVar = bVar.c;
                    synchronized (gVar.k) {
                        gVar.i = k;
                    }
                    synchronized (bVar.a) {
                        bVar.c.c(list);
                    }
                    if (((L) j.getLifecycle()).d.a(B.d)) {
                        t(j);
                    }
                } catch (CameraUseCaseAdapter$CameraException e) {
                    throw new IllegalArgumentException(e);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public C d() {
        F fK = null;
        if (!((List) this.f).isEmpty()) {
            com.quizlet.data.interactor.set.c cVar = new com.quizlet.data.interactor.set.c(0);
            cVar.r(y.f);
            if (org.apache.commons.lang3.e.d((String) this.e)) {
                Pattern pattern = w.e;
                cVar.h("data", null, C1412o.g(AbstractC3347h2.d("application/x-www-form-urlencoded; charset=UTF-8"), (String) this.e));
            }
            for (C4115c0 c4115c0 : (List) this.f) {
                c4115c0.getClass();
                Pattern pattern2 = w.e;
                cVar.h("image[]", c4115c0.a, F.c(AbstractC3347h2.d("image/*"), c4115c0.b));
            }
            fK = cVar.k();
        } else if (((String) this.e) != null) {
            Pattern pattern3 = w.e;
            fK = C1412o.g(AbstractC3347h2.d("application/x-www-form-urlencoded; charset=UTF-8"), (String) this.e);
        }
        com.quizlet.remote.model.notes.e eVar = new com.quizlet.remote.model.notes.e(13);
        eVar.r((String) this.b);
        r headers = ((h) this.d).d();
        Intrinsics.checkNotNullParameter(headers, "headers");
        eVar.d = headers.e();
        eVar.n((String) this.c, fK);
        return eVar.i();
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return S.f(this, list);
    }

    @Override // com.google.android.gms.ads.internal.d
    public void f(View view) {
        C2881yn c2881yn = (C2881yn) ((C2752vn) this.f).e;
        Vp vp = (Vp) this.d;
        C2149hk c2149hk = new C2149hk(new Ts(vp, 27), null, 1);
        C2326lq c2326lq = new C2326lq((C1849aq) this.c, vp, (String) null);
        C1813Ze c1813Ze = (C1813Ze) c2881yn.b;
        C1807Ye c1807Ye = new C1807Ye(c1813Ze.b, c1813Ze.c, c2326lq, c2149hk);
        S4 s4 = new S4(c1807Ye, 22);
        Os os = (Os) this.e;
        synchronized (os) {
            os.b = s4;
        }
        ((C2313ld) this.b).c(c1807Ye.O());
    }

    public androidx.camera.lifecycle.b g(J j, androidx.camera.core.internal.g gVar) {
        synchronized (this.b) {
            try {
                AbstractC3242q6.c("LifecycleCamera already exists for the given LifecycleOwner and set of cameras", ((HashMap) this.c).get(new androidx.camera.lifecycle.a(j, gVar.e)) == null);
                androidx.camera.lifecycle.b bVar = new androidx.camera.lifecycle.b(j, gVar);
                if (((ArrayList) gVar.w()).isEmpty()) {
                    bVar.e();
                }
                if (((L) j.getLifecycle()).d == B.a) {
                    return bVar;
                }
                p(bVar);
                return bVar;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable h(java.util.ArrayList r13, kotlin.coroutines.jvm.internal.c r14) {
        /*
            Method dump skipped, instructions count: 256
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.studysetwithcreatorinclass.g.h(java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable i(java.util.ArrayList r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.data.repository.studysetwithcreatorinclass.d
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.data.repository.studysetwithcreatorinclass.d r0 = (com.quizlet.data.repository.studysetwithcreatorinclass.d) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.repository.studysetwithcreatorinclass.d r0 = new com.quizlet.data.repository.studysetwithcreatorinclass.d
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            java.util.List r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L74
        L29:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Object r8 = r6.b
            com.quizlet.data.interactor.school.b r8 = (com.quizlet.data.interactor.school.b) r8
            java.lang.Object r8 = r8.c
            com.quizlet.remote.model.union.studysetwithcreatorinclass.e r8 = (com.quizlet.remote.model.union.studysetwithcreatorinclass.e) r8
            java.lang.String r2 = "classIds"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r2)
            com.quizlet.remote.model.union.studysetwithcreatorinclass.b r2 = new com.quizlet.remote.model.union.studysetwithcreatorinclass.b
            r4 = 0
            r5 = 0
            r2.<init>(r8, r7, r5, r4)
            kotlinx.coroutines.y r8 = r8.d
            io.reactivex.rxjava3.internal.operators.flowable.b r8 = com.google.android.gms.internal.mlkit_vision_camera.L1.e(r8, r2)
            com.google.firebase.messaging.p r2 = new com.google.firebase.messaging.p
            r4 = 15
            r2.<init>(r6, r4)
            io.reactivex.rxjava3.internal.operators.single.g r8 = r8.e(r2)
            java.lang.String r2 = "flatMap(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r2)
            com.quizlet.data.repository.studysetwithcreatorinclass.f r2 = com.quizlet.data.repository.studysetwithcreatorinclass.f.c
            io.reactivex.rxjava3.internal.operators.single.g r8 = r8.g(r2)
            java.lang.String r2 = "map(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r2)
            r0.j = r7
            r0.m = r3
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r8, r0)
            if (r8 != r1) goto L74
            return r1
        L74:
            java.lang.String r0 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r0)
            java.util.Map r8 = (java.util.Map) r8
            java.util.LinkedHashMap r0 = new java.util.LinkedHashMap
            r1 = 10
            int r1 = kotlin.collections.C.q(r7, r1)
            int r1 = kotlin.collections.U.a(r1)
            r2 = 16
            if (r1 >= r2) goto L8c
            r1 = r2
        L8c:
            r0.<init>(r1)
            java.util.Iterator r7 = r7.iterator()
        L93:
            boolean r1 = r7.hasNext()
            if (r1 == 0) goto Lb7
            java.lang.Object r1 = r7.next()
            r2 = r1
            java.lang.Number r2 = (java.lang.Number) r2
            long r2 = r2.longValue()
            java.lang.Long r4 = new java.lang.Long
            r4.<init>(r2)
            java.lang.Object r2 = r8.get(r4)
            if (r2 != 0) goto Lb1
            kotlin.collections.K r2 = kotlin.collections.K.a
        Lb1:
            java.util.List r2 = (java.util.List) r2
            r0.put(r1, r2)
            goto L93
        Lb7:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.studysetwithcreatorinclass.g.i(java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable j(long r9, kotlin.coroutines.jvm.internal.c r11) throws java.lang.Throwable {
        /*
            r8 = this;
            boolean r0 = r11 instanceof com.quizlet.data.repository.studysetwithcreatorinclass.e
            if (r0 == 0) goto L13
            r0 = r11
            com.quizlet.data.repository.studysetwithcreatorinclass.e r0 = (com.quizlet.data.repository.studysetwithcreatorinclass.e) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.data.repository.studysetwithcreatorinclass.e r0 = new com.quizlet.data.repository.studysetwithcreatorinclass.e
            r0.<init>(r8, r11)
        L18:
            java.lang.Object r11 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            com.quizlet.data.repository.studysetwithcreatorinclass.g r9 = r0.k
            com.quizlet.data.repository.studysetwithcreatorinclass.g r10 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L5a
        L2b:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            java.lang.Object r11 = r8.b
            com.quizlet.data.interactor.school.b r11 = (com.quizlet.data.interactor.school.b) r11
            java.lang.Object r11 = r11.c
            com.quizlet.remote.model.union.studysetwithcreatorinclass.e r11 = (com.quizlet.remote.model.union.studysetwithcreatorinclass.e) r11
            r0.j = r8
            r0.k = r8
            r0.n = r3
            com.quizlet.remote.model.union.studysetwithcreatorinclass.c r2 = new com.quizlet.remote.model.union.studysetwithcreatorinclass.c
            r3 = 0
            r2.<init>(r11, r9, r3)
            com.quizlet.remote.model.union.studysetwithcreatorinclass.d r9 = new com.quizlet.remote.model.union.studysetwithcreatorinclass.d
            r9.<init>(r11, r2, r3)
            kotlinx.coroutines.y r10 = r11.d
            java.lang.Object r11 = kotlinx.coroutines.E.J(r10, r9, r0)
            if (r11 != r1) goto L58
            return r1
        L58:
            r9 = r8
            r10 = r9
        L5a:
            com.quizlet.data.repository.studysetwithcreatorinclass.a r11 = (com.quizlet.data.repository.studysetwithcreatorinclass.a) r11
            io.reactivex.rxjava3.core.p r10 = r10.m(r11)
            com.quizlet.infra.legacysyncengine.net.request.g r0 = io.reactivex.rxjava3.internal.functions.d.d
            com.quizlet.infra.legacysyncengine.net.request.g r1 = io.reactivex.rxjava3.internal.functions.d.e
            r10.i(r0, r1)
            r9.getClass()
            java.util.ArrayList r9 = new java.util.ArrayList
            r9.<init>()
            java.util.List r10 = r11.a
            java.util.Iterator r10 = r10.iterator()
        L75:
            boolean r0 = r10.hasNext()
            if (r0 == 0) goto L94
            java.lang.Object r0 = r10.next()
            r1 = r0
            com.quizlet.data.model.F r1 = (com.quizlet.data.model.F) r1
            java.lang.Boolean r2 = r1.h
            java.lang.Boolean r3 = java.lang.Boolean.TRUE
            boolean r2 = kotlin.jvm.internal.Intrinsics.b(r2, r3)
            if (r2 != 0) goto L75
            boolean r1 = r1.k
            if (r1 != 0) goto L75
            r9.add(r0)
            goto L75
        L94:
            java.util.List r10 = r11.b
            java.lang.Object r10 = kotlin.collections.CollectionsKt.firstOrNull(r10)
            com.quizlet.data.model.StudySetWithCreator r10 = (com.quizlet.data.model.StudySetWithCreator) r10
            if (r10 != 0) goto La1
            kotlin.collections.K r9 = kotlin.collections.K.a
            return r9
        La1:
            java.util.ArrayList r11 = new java.util.ArrayList
            r0 = 10
            int r0 = kotlin.collections.C.q(r9, r0)
            r11.<init>(r0)
            java.util.Iterator r9 = r9.iterator()
        Lb0:
            boolean r0 = r9.hasNext()
            if (r0 == 0) goto Ld3
            java.lang.Object r0 = r9.next()
            com.quizlet.data.model.F r0 = (com.quizlet.data.model.F) r0
            com.quizlet.data.model.c2 r1 = new com.quizlet.data.model.c2
            long r4 = r0.g
            long r2 = r0.b
            java.lang.Long r7 = java.lang.Long.valueOf(r2)
            boolean r6 = r0.f
            com.quizlet.data.model.StudySet r2 = r10.a
            com.quizlet.data.model.User r3 = r10.b
            r1.<init>(r2, r3, r4, r6, r7)
            r11.add(r1)
            goto Lb0
        Ld3:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.studysetwithcreatorinclass.g.j(long, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public androidx.camera.lifecycle.c k(J j) {
        synchronized (this.b) {
            try {
                for (androidx.camera.lifecycle.c cVar : ((HashMap) this.d).keySet()) {
                    if (j.equals(cVar.b)) {
                        return cVar;
                    }
                }
                return null;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public boolean l(J j) {
        synchronized (this.b) {
            try {
                androidx.camera.lifecycle.c cVarK = k(j);
                if (cVarK == null) {
                    return false;
                }
                Iterator it2 = ((Set) ((HashMap) this.d).get(cVarK)).iterator();
                while (it2.hasNext()) {
                    androidx.camera.lifecycle.b bVar = (androidx.camera.lifecycle.b) ((HashMap) this.c).get((androidx.camera.lifecycle.a) it2.next());
                    bVar.getClass();
                    if (!bVar.c().isEmpty()) {
                        return true;
                    }
                }
                return false;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public p m(final a aVar) {
        final int i = 0;
        Object obj = null;
        io.reactivex.rxjava3.internal.operators.completable.m mVar = new io.reactivex.rxjava3.internal.operators.completable.m(((com.quizlet.local.ormlite.models.bookmark.a) this.c).a(aVar.a), new io.reactivex.rxjava3.functions.h(this) { // from class: com.quizlet.data.repository.studysetwithcreatorinclass.b
            public final /* synthetic */ g b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.h
            public final Object apply(Object obj2) {
                Throwable e = (Throwable) obj2;
                switch (i) {
                    case 0:
                        Intrinsics.checkNotNullParameter(e, "e");
                        ((org.slf4j.b) this.b.f).h("Error importing remote ClassSet data", e);
                        return aVar.a;
                    default:
                        Intrinsics.checkNotNullParameter(e, "e");
                        ((org.slf4j.b) this.b.f).h("Error importing remote StudySetWithCreator data", e);
                        return aVar.b;
                }
            }
        }, obj, 2);
        Intrinsics.checkNotNullExpressionValue(mVar, "onErrorReturn(...)");
        final int i2 = 1;
        io.reactivex.rxjava3.internal.operators.completable.m mVar2 = new io.reactivex.rxjava3.internal.operators.completable.m(((com.quizlet.local.ormlite.models.studysetwithcreator.a) this.d).a(aVar.b), new io.reactivex.rxjava3.functions.h(this) { // from class: com.quizlet.data.repository.studysetwithcreatorinclass.b
            public final /* synthetic */ g b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.h
            public final Object apply(Object obj2) {
                Throwable e = (Throwable) obj2;
                switch (i2) {
                    case 0:
                        Intrinsics.checkNotNullParameter(e, "e");
                        ((org.slf4j.b) this.b.f).h("Error importing remote ClassSet data", e);
                        return aVar.a;
                    default:
                        Intrinsics.checkNotNullParameter(e, "e");
                        ((org.slf4j.b) this.b.f).h("Error importing remote StudySetWithCreator data", e);
                        return aVar.b;
                }
            }
        }, obj, 2);
        Intrinsics.checkNotNullExpressionValue(mVar2, "onErrorReturn(...)");
        p pVarP = p.p(mVar, mVar2, new f(2));
        Intrinsics.checkNotNullExpressionValue(pVarP, "Single.zip(s1, s2, BiFun…-> zipper.invoke(t, u) })");
        return pVarP;
    }

    public synchronized boolean n() {
        boolean zH;
        Boolean bool = (Boolean) this.e;
        if (bool != null) {
            zH = bool.booleanValue();
        } else {
            try {
                zH = ((com.google.firebase.h) this.b).h();
            } catch (IllegalStateException unused) {
                zH = false;
            }
        }
        Log.isLoggable("FirebaseCrashlytics", 3);
        return zH;
    }

    @Override // com.quizlet.remote.mapper.base.a
    /* renamed from: o, reason: merged with bridge method [inline-methods] */
    public ArrayList c(com.quizlet.remote.model.studymaterial.a remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        List list = remote.h;
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            if (!((RemoteUser) obj).l) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(com.quizlet.quizletandroid.ui.activitycenter.models.a.b((RemoteUser) it2.next()));
        }
        int iA = U.a(kotlin.collections.C.q(arrayList2, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        Iterator it3 = arrayList2.iterator();
        while (it3.hasNext()) {
            Object next = it3.next();
            linkedHashMap.put(Long.valueOf(((User) next).a), next);
        }
        ArrayList arrayList3 = new ArrayList();
        for (Object obj2 : remote.b) {
            if (!((RemoteQuestion) obj2).k) {
                arrayList3.add(obj2);
            }
        }
        ArrayList arrayList4 = new ArrayList(kotlin.collections.C.q(arrayList3, 10));
        Iterator it4 = arrayList3.iterator();
        while (it4.hasNext()) {
            arrayList4.add(((com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c) this.b).c((RemoteQuestion) it4.next()));
        }
        int iA2 = U.a(kotlin.collections.C.q(arrayList4, 10));
        if (iA2 < 16) {
            iA2 = 16;
        }
        LinkedHashMap linkedHashMap2 = new LinkedHashMap(iA2);
        Iterator it5 = arrayList4.iterator();
        while (it5.hasNext()) {
            Object next2 = it5.next();
            linkedHashMap2.put(((Question) next2).d, next2);
        }
        ArrayList arrayList5 = new ArrayList();
        for (Object obj3 : remote.c) {
            if (!((RemoteSet) obj3).y) {
                arrayList5.add(obj3);
            }
        }
        ArrayList arrayList6 = new ArrayList(kotlin.collections.C.q(arrayList5, 10));
        Iterator it6 = arrayList5.iterator();
        while (it6.hasNext()) {
            arrayList6.add(com.quizlet.quizletandroid.ui.profile.data.b.b((RemoteSet) it6.next()));
        }
        ArrayList arrayList7 = new ArrayList(kotlin.collections.C.q(arrayList6, 10));
        Iterator it7 = arrayList6.iterator();
        while (it7.hasNext()) {
            StudySet studySet = (StudySet) it7.next();
            arrayList7.add(new StudySetWithCreator(studySet, (User) linkedHashMap.get(Long.valueOf(studySet.e))));
        }
        int iA3 = U.a(kotlin.collections.C.q(arrayList7, 10));
        if (iA3 < 16) {
            iA3 = 16;
        }
        LinkedHashMap linkedHashMap3 = new LinkedHashMap(iA3);
        Iterator it8 = arrayList7.iterator();
        while (it8.hasNext()) {
            Object next3 = it8.next();
            linkedHashMap3.put(String.valueOf(((StudySetWithCreator) next3).a.a), next3);
        }
        ArrayList arrayList8 = new ArrayList();
        for (Object obj4 : remote.d) {
            if (!((RemoteFolder) obj4).i) {
                arrayList8.add(obj4);
            }
        }
        ArrayList arrayList9 = new ArrayList(kotlin.collections.C.q(arrayList8, 10));
        Iterator it9 = arrayList8.iterator();
        while (it9.hasNext()) {
            arrayList9.add(((com.quizlet.quizletandroid.ui.folder.logging.a) this.c).g((RemoteFolder) it9.next()));
        }
        ArrayList arrayList10 = new ArrayList();
        Iterator it10 = arrayList9.iterator();
        while (it10.hasNext()) {
            Object next4 = it10.next();
            if (next4 instanceof CreatedFolder) {
                arrayList10.add(next4);
            }
        }
        ArrayList arrayList11 = new ArrayList(kotlin.collections.C.q(arrayList10, 10));
        Iterator it11 = arrayList10.iterator();
        while (it11.hasNext()) {
            CreatedFolder createdFolder = (CreatedFolder) it11.next();
            arrayList11.add(new CreatedFolderWithCreator(createdFolder, (User) linkedHashMap.get(Long.valueOf(createdFolder.h()))));
        }
        int iA4 = U.a(kotlin.collections.C.q(arrayList11, 10));
        if (iA4 < 16) {
            iA4 = 16;
        }
        LinkedHashMap linkedHashMap4 = new LinkedHashMap(iA4);
        Iterator it12 = arrayList11.iterator();
        while (it12.hasNext()) {
            Object next5 = it12.next();
            linkedHashMap4.put(String.valueOf(((CreatedFolderWithCreator) next5).a.a()), next5);
        }
        ArrayList arrayList12 = new ArrayList();
        for (Object obj5 : remote.e) {
            if (!((RemoteTextbook) obj5).n) {
                arrayList12.add(obj5);
            }
        }
        ArrayList arrayList13 = new ArrayList(kotlin.collections.C.q(arrayList12, 10));
        Iterator it13 = arrayList12.iterator();
        while (it13.hasNext()) {
            arrayList13.add(((k) this.e).c((RemoteTextbook) it13.next()));
        }
        int iA5 = U.a(kotlin.collections.C.q(arrayList13, 10));
        if (iA5 < 16) {
            iA5 = 16;
        }
        LinkedHashMap linkedHashMap5 = new LinkedHashMap(iA5);
        Iterator it14 = arrayList13.iterator();
        while (it14.hasNext()) {
            Object next6 = it14.next();
            linkedHashMap5.put(((Textbook) next6).b, next6);
        }
        ArrayList arrayList14 = new ArrayList();
        for (Object obj6 : remote.f) {
            if (!((RemoteExerciseDetails) obj6).p) {
                arrayList14.add(obj6);
            }
        }
        ArrayList arrayList15 = new ArrayList(kotlin.collections.C.q(arrayList14, 10));
        Iterator it15 = arrayList14.iterator();
        while (it15.hasNext()) {
            arrayList15.add(((com.quizlet.data.repository.course.membership.c) this.f).c((RemoteExerciseDetails) it15.next()));
        }
        int iA6 = U.a(kotlin.collections.C.q(arrayList15, 10));
        if (iA6 < 16) {
            iA6 = 16;
        }
        LinkedHashMap linkedHashMap6 = new LinkedHashMap(iA6);
        Iterator it16 = arrayList15.iterator();
        while (it16.hasNext()) {
            Object next7 = it16.next();
            linkedHashMap6.put(((ExerciseDetails) next7).b, next7);
        }
        ArrayList arrayList16 = new ArrayList();
        for (Object obj7 : remote.g) {
            if (!Intrinsics.b(((RemoteStudyNote) obj7).d, Boolean.TRUE)) {
                arrayList16.add(obj7);
            }
        }
        ArrayList arrayList17 = new ArrayList(kotlin.collections.C.q(arrayList16, 10));
        Iterator it17 = arrayList16.iterator();
        while (it17.hasNext()) {
            arrayList17.add(((com.quizlet.quizletandroid.ui.profile.data.b) this.d).a((RemoteStudyNote) it17.next()));
        }
        int iA7 = U.a(kotlin.collections.C.q(arrayList17, 10));
        LinkedHashMap linkedHashMap7 = new LinkedHashMap(iA7 >= 16 ? iA7 : 16);
        Iterator it18 = arrayList17.iterator();
        while (it18.hasNext()) {
            Object next8 = it18.next();
            linkedHashMap7.put(((NotesToValueInfo) next8).a, next8);
        }
        ArrayList arrayList18 = new ArrayList();
        for (M1 m1 : remote.a) {
            Object studyMaterialItem$FlashcardSetItem = null;
            switch (com.quizlet.remote.model.studymaterial.b.a[m1.b().ordinal()]) {
                case 1:
                    StudySetWithCreator studySetWithCreator = (StudySetWithCreator) linkedHashMap3.get(m1.c());
                    if (studySetWithCreator != null) {
                        studyMaterialItem$FlashcardSetItem = new StudyMaterialItem$FlashcardSetItem(m1, studySetWithCreator);
                        break;
                    }
                    break;
                case 2:
                    CreatedFolderWithCreator createdFolderWithCreator = (CreatedFolderWithCreator) linkedHashMap4.get(m1.c());
                    if (createdFolderWithCreator != null) {
                        studyMaterialItem$FlashcardSetItem = new StudyMaterialItem$FolderItem(m1, createdFolderWithCreator);
                        break;
                    }
                    break;
                case 3:
                    Textbook textbook = (Textbook) linkedHashMap5.get(m1.c());
                    if (textbook != null) {
                        studyMaterialItem$FlashcardSetItem = new StudyMaterialItem$TextbookItem(m1, textbook);
                        break;
                    }
                    break;
                case 4:
                    ExerciseDetails exerciseDetails = (ExerciseDetails) linkedHashMap6.get(m1.c());
                    if (exerciseDetails != null) {
                        studyMaterialItem$FlashcardSetItem = new StudyMaterialItem$TextbookExerciseItem(m1, exerciseDetails);
                        break;
                    }
                    break;
                case 5:
                    Question question = (Question) linkedHashMap2.get(m1.c());
                    if (question != null) {
                        studyMaterialItem$FlashcardSetItem = new StudyMaterialItem$ExplanationQuestionItem(m1, question);
                        break;
                    }
                    break;
                case 6:
                    NotesToValueInfo notesToValueInfo = (NotesToValueInfo) linkedHashMap7.get(m1.c());
                    if (notesToValueInfo != null) {
                        studyMaterialItem$FlashcardSetItem = new StudyMaterialItem$NoteItem(m1, notesToValueInfo);
                        break;
                    }
                    break;
                case 7:
                case 8:
                    break;
                default:
                    throw new NoWhenBranchMatchedException();
            }
            if (studyMaterialItem$FlashcardSetItem != null) {
                arrayList18.add(studyMaterialItem$FlashcardSetItem);
            }
        }
        return arrayList18;
    }

    public void p(androidx.camera.lifecycle.b bVar) {
        J j;
        synchronized (this.b) {
            try {
                synchronized (bVar.a) {
                    j = bVar.b;
                }
                androidx.camera.core.internal.g gVar = bVar.c;
                androidx.camera.lifecycle.a aVar = new androidx.camera.lifecycle.a(j, androidx.camera.core.internal.g.t(gVar.p, gVar.q));
                androidx.camera.lifecycle.c cVarK = k(j);
                Set hashSet = cVarK != null ? (Set) ((HashMap) this.d).get(cVarK) : new HashSet();
                hashSet.add(aVar);
                ((HashMap) this.c).put(aVar, bVar);
                if (cVarK == null) {
                    androidx.camera.lifecycle.c cVar = new androidx.camera.lifecycle.c(j, this);
                    ((HashMap) this.d).put(cVar, hashSet);
                    j.getLifecycle().a(cVar);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void q(String str) {
        Pattern pattern = C5083l.j;
        s sVar = (s) this.e;
        C5083l c5083lL = AbstractC3335e2.l(sVar, str);
        n nVar = (n) this.b;
        if (c5083lL != null) {
            nVar.a(sVar, A.b(c5083lL));
        }
        s sVar2 = (s) this.f;
        C5083l c5083lL2 = AbstractC3335e2.l(sVar2, str);
        if (c5083lL2 != null) {
            nVar.a(sVar2, A.b(c5083lL2));
        }
    }

    public void r(String str) {
        kotlin.text.m mVarB;
        String value = (str == null || (mVarB = new Regex("cf_clearance=\\S*;", kotlin.text.s.b).b(str)) == null) ? null : mVarB.getValue();
        timber.log.c.a.m("cfClearanceCookie: %s", value);
        if (value == null) {
            return;
        }
        q(value);
        E.A((kotlinx.coroutines.internal.d) this.d, null, null, new com.quizlet.security.challenge.core.b(this, value, null), 3);
    }

    public void s(Object obj, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        ((LinkedHashMap) this.b).put(key, obj);
        X x = (X) ((LinkedHashMap) this.d).get(key);
        if (x != null) {
            ((s0) x).l(obj);
        }
        X x2 = (X) ((LinkedHashMap) this.e).get(key);
        if (x2 != null) {
            ((s0) x2).l(obj);
        }
    }

    public void t(J j) {
        synchronized (this.b) {
            try {
                if (l(j)) {
                    if (((ArrayDeque) this.e).isEmpty()) {
                        ((ArrayDeque) this.e).push(j);
                    } else {
                        androidx.camera.camera2.internal.concurrent.a aVar = (androidx.camera.camera2.internal.concurrent.a) this.f;
                        if (aVar == null || aVar.b != 2) {
                            J j2 = (J) ((ArrayDeque) this.e).peek();
                            if (!j.equals(j2)) {
                                v(j2);
                                ((ArrayDeque) this.e).remove(j);
                                ((ArrayDeque) this.e).push(j);
                            }
                        }
                    }
                    x(j);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public String toString() {
        switch (this.a) {
            case 11:
                return ((String) this.c) + " " + ((String) this.b);
            default:
                return super.toString();
        }
    }

    public void u(J j) {
        synchronized (this.b) {
            try {
                ((ArrayDeque) this.e).remove(j);
                v(j);
                if (!((ArrayDeque) this.e).isEmpty()) {
                    x((J) ((ArrayDeque) this.e).peek());
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void v(J j) {
        synchronized (this.b) {
            try {
                androidx.camera.lifecycle.c cVarK = k(j);
                if (cVarK == null) {
                    return;
                }
                Iterator it2 = ((Set) ((HashMap) this.d).get(cVarK)).iterator();
                while (it2.hasNext()) {
                    androidx.camera.lifecycle.b bVar = (androidx.camera.lifecycle.b) ((HashMap) this.c).get((androidx.camera.lifecycle.a) it2.next());
                    bVar.getClass();
                    bVar.e();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void w() {
        J j;
        synchronized (this.b) {
            Iterator it2 = ((HashMap) this.c).keySet().iterator();
            while (it2.hasNext()) {
                androidx.camera.lifecycle.b bVar = (androidx.camera.lifecycle.b) ((HashMap) this.c).get((androidx.camera.lifecycle.a) it2.next());
                synchronized (bVar.a) {
                    androidx.camera.core.internal.g gVar = bVar.c;
                    gVar.z((ArrayList) gVar.w());
                }
                synchronized (bVar.a) {
                    j = bVar.b;
                }
                u(j);
            }
        }
    }

    public void x(J j) {
        synchronized (this.b) {
            try {
                Iterator it2 = ((Set) ((HashMap) this.d).get(k(j))).iterator();
                while (it2.hasNext()) {
                    androidx.camera.lifecycle.b bVar = (androidx.camera.lifecycle.b) ((HashMap) this.c).get((androidx.camera.lifecycle.a) it2.next());
                    bVar.getClass();
                    if (!bVar.c().isEmpty()) {
                        bVar.o();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public com.google.common.util.concurrent.e y() {
        synchronized (this.b) {
            try {
                if (((SharedPreferences) this.d) == null) {
                    this.d = ((Context) this.c).getSharedPreferences("google_ads_flags_meta", 0);
                }
            } finally {
            }
        }
        SharedPreferences sharedPreferences = (SharedPreferences) this.d;
        long j = sharedPreferences != null ? sharedPreferences.getLong("js_last_update", 0L) : 0L;
        j.C.k.getClass();
        if (System.currentTimeMillis() - j < ((Long) W7.d.o()).longValue()) {
            return Tv.b;
        }
        return AbstractC2025es.L(((com.google.android.gms.ads.internal.c) this.e).a(z((Context) this.c, (VersionInfoParcel) this.f)), new C1804Yb(this, 0), AbstractC2270kd.g);
    }

    @Override // com.google.android.gms.ads.internal.d
    public void zzb() {
    }

    public g(C2752vn c2752vn, C2313ld c2313ld, C1849aq c1849aq, Vp vp, Os os) {
        this.a = 5;
        this.b = c2313ld;
        this.c = c1849aq;
        this.d = vp;
        this.e = os;
        this.f = c2752vn;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public g(A7 a7, WebView webView) {
        this.a = 6;
        int i = 0;
        HashMap map = new HashMap();
        this.e = map;
        this.f = new Vr();
        if (AbstractC1972di.M.b) {
            this.b = a7;
            this.c = webView;
            m mVar = (m) this.d;
            if ((mVar == null ? null : (View) mVar.get()) != webView) {
                Iterator it2 = map.values().iterator();
                while (it2.hasNext()) {
                    ((Hr) it2.next()).b(webView);
                }
                this.d = new m(webView);
            }
            if (AbstractC3379p2.c("WEB_MESSAGE_LISTENER")) {
                int i2 = i.a;
                if (androidx.webkit.internal.s.e.b()) {
                    ((WebViewProviderBoundaryInterface) i.b((WebView) this.c).b).removeWebMessageListener("omidJsSessionService");
                    i.a((WebView) this.c, "omidJsSessionService", new HashSet(Arrays.asList("*")), new Lr(this, i));
                    return;
                }
                throw androidx.webkit.internal.s.a();
            }
            throw new UnsupportedOperationException("The JavaScriptSessionService cannot be supported in this WebView version.");
        }
        throw new IllegalStateException("Method called before OM SDK activation");
    }

    public g(com.airbnb.lottie.model.animatable.a aVar, com.airbnb.lottie.model.animatable.b bVar, com.airbnb.lottie.model.animatable.b bVar2, com.airbnb.lottie.model.animatable.b bVar3, com.airbnb.lottie.model.animatable.b bVar4) {
        this.a = 3;
        this.b = aVar;
        this.c = bVar;
        this.d = bVar2;
        this.e = bVar3;
        this.f = bVar4;
    }

    public g(Context context, AbstractC5040y ioDispatcher) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = context;
        this.c = ioDispatcher;
        this.d = new D(new com.google.firebase.crashlytics.internal.metadata.p(1));
        final int i = 0;
        this.e = l.b(new Function0(this) { // from class: com.quizlet.edgy.utils.a
            public final /* synthetic */ g b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i) {
                    case 0:
                        D d = (D) this.b.d;
                        d.getClass();
                        return d.a(AllCountries.class, com.squareup.moshi.internal.b.a, null);
                    default:
                        D d2 = (D) this.b.d;
                        d2.getClass();
                        return d2.a(AllStates.class, com.squareup.moshi.internal.b.a, null);
                }
            }
        });
        final int i2 = 1;
        this.f = l.b(new Function0(this) { // from class: com.quizlet.edgy.utils.a
            public final /* synthetic */ g b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                    case 0:
                        D d = (D) this.b.d;
                        d.getClass();
                        return d.a(AllCountries.class, com.squareup.moshi.internal.b.a, null);
                    default:
                        D d2 = (D) this.b.d;
                        d2.getClass();
                        return d2.a(AllStates.class, com.squareup.moshi.internal.b.a, null);
                }
            }
        });
    }

    public g(UserInfoCache userInfoCache, com.quizlet.infra.legacysyncengine.net.c loader, com.quizlet.features.infra.studysetting.managers.a studySettingManager, com.quizlet.featuregate.features.studymodes.learn.a defaultStudyPathConfiguration, androidx.work.impl.model.c userProperties) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(studySettingManager, "studySettingManager");
        Intrinsics.checkNotNullParameter(defaultStudyPathConfiguration, "defaultStudyPathConfiguration");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        this.b = userInfoCache;
        this.c = loader;
        this.d = studySettingManager;
        this.e = defaultStudyPathConfiguration;
        this.f = userProperties;
    }

    public g(n cookieJar, com.google.mlkit.common.sdkinternal.model.a apiUrlProvider, com.quizlet.local.datastore.preferences.J cookieStoreManager, kotlinx.coroutines.internal.d ioScope) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(cookieJar, "cookieJar");
        Intrinsics.checkNotNullParameter(apiUrlProvider, "apiUrlProvider");
        Intrinsics.checkNotNullParameter(cookieStoreManager, "cookieStoreManager");
        Intrinsics.checkNotNullParameter(ioScope, "ioScope");
        this.b = cookieJar;
        this.c = cookieStoreManager;
        this.d = ioScope;
        Intrinsics.checkNotNullParameter("https://api.quizlet.com/", "<this>");
        C1372j c1372j = new C1372j();
        c1372j.l(null, "https://api.quizlet.com/");
        this.e = c1372j.d();
        Intrinsics.checkNotNullParameter("https://quizlet.com", "<this>");
        C1372j c1372j2 = new C1372j();
        c1372j2.l(null, "https://quizlet.com");
        this.f = c1372j2.d();
    }

    public g(com.quizlet.data.interactor.school.b factory, com.quizlet.local.ormlite.models.bookmark.a classSetLocal, com.quizlet.local.ormlite.models.studysetwithcreator.a studySetWithCreatorLocal, com.quizlet.data.connectivity.a networkStatus, org.slf4j.b logger) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(classSetLocal, "classSetLocal");
        Intrinsics.checkNotNullParameter(studySetWithCreatorLocal, "studySetWithCreatorLocal");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = factory;
        this.c = classSetLocal;
        this.d = studySetWithCreatorLocal;
        this.e = networkStatus;
        this.f = logger;
    }

    public g(com.quizlet.quizletandroid.ui.activitycenter.models.a userMapper, com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c explanationQuestionMapper, com.quizlet.quizletandroid.ui.profile.data.b flashcardSetMapper, com.quizlet.quizletandroid.ui.folder.logging.a folderMapper, com.quizlet.quizletandroid.ui.profile.data.b studyNoteMapper, k textbookMapper, com.quizlet.data.repository.course.membership.c textbookExerciseMapper) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(userMapper, "userMapper");
        Intrinsics.checkNotNullParameter(explanationQuestionMapper, "explanationQuestionMapper");
        Intrinsics.checkNotNullParameter(flashcardSetMapper, "flashcardSetMapper");
        Intrinsics.checkNotNullParameter(folderMapper, "folderMapper");
        Intrinsics.checkNotNullParameter(studyNoteMapper, "studyNoteMapper");
        Intrinsics.checkNotNullParameter(textbookMapper, "textbookMapper");
        Intrinsics.checkNotNullParameter(textbookExerciseMapper, "textbookExerciseMapper");
        this.b = explanationQuestionMapper;
        this.c = folderMapper;
        this.d = studyNoteMapper;
        this.e = textbookMapper;
        this.f = textbookExerciseMapper;
    }

    public g(Map initialState) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(initialState, "initialState");
        this.b = V.m(initialState);
        this.c = new LinkedHashMap();
        this.d = new LinkedHashMap();
        this.e = new LinkedHashMap();
        this.f = new C0034f(this, 2);
    }

    public g(com.google.firebase.h hVar) {
        PackageManager packageManager;
        ApplicationInfo applicationInfo;
        Bundle bundle;
        this.a = 8;
        this.c = new Object();
        this.d = new com.google.android.gms.tasks.f();
        this.f = new com.google.android.gms.tasks.f();
        hVar.a();
        Context context = hVar.a;
        this.b = hVar;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.google.firebase.crashlytics", 0);
        Boolean boolValueOf = sharedPreferences.contains("firebase_crashlytics_collection_enabled") ? Boolean.valueOf(sharedPreferences.getBoolean("firebase_crashlytics_collection_enabled", true)) : null;
        if (boolValueOf == null) {
            try {
                packageManager = context.getPackageManager();
            } catch (PackageManager.NameNotFoundException e) {
                Log.e("FirebaseCrashlytics", "Could not read data collection permission from manifest", e);
            }
            Boolean boolValueOf2 = (packageManager == null || (applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), 128)) == null || (bundle = applicationInfo.metaData) == null || !bundle.containsKey("firebase_crashlytics_collection_enabled")) ? null : Boolean.valueOf(applicationInfo.metaData.getBoolean("firebase_crashlytics_collection_enabled"));
            boolValueOf = boolValueOf2 == null ? null : Boolean.valueOf(Boolean.TRUE.equals(boolValueOf2));
        }
        this.e = boolValueOf;
        synchronized (this.c) {
            try {
                if (n()) {
                    ((com.google.android.gms.tasks.f) this.d).d(null);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public g(int i) {
        this.a = i;
        switch (i) {
            case 7:
                break;
            case 11:
                this.d = new h(3);
                this.f = new ArrayList();
                break;
            default:
                this.b = new Object();
                this.c = new HashMap();
                this.d = new HashMap();
                this.e = new ArrayDeque();
                break;
        }
    }
}
