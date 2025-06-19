package com.quizlet.data.repository.user;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import androidx.activity.compose.g;
import androidx.camera.core.M;
import androidx.camera.core.O;
import androidx.camera.core.impl.EnumC0174m;
import androidx.camera.core.impl.EnumC0175n;
import androidx.camera.core.impl.EnumC0176o;
import androidx.camera.core.impl.InterfaceC0177p;
import androidx.lifecycle.L;
import androidx.paging.B;
import androidx.paging.C;
import androidx.paging.C1325l;
import androidx.paging.D;
import androidx.paging.E;
import androidx.paging.F;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.internal.measurement.C2967b;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.material.bottomsheet.i;
import com.google.firebase.analytics.FirebaseAnalytics;
import com.quizlet.data.model.C0;
import com.quizlet.data.model.C4113b2;
import com.quizlet.data.model.C4117c2;
import com.quizlet.data.model.C4136i1;
import com.quizlet.data.model.C4154o1;
import com.quizlet.data.model.C4172v;
import com.quizlet.data.model.School;
import com.quizlet.data.model.StudySet;
import com.quizlet.data.model.User;
import com.quizlet.data.model.j2;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;
import com.quizlet.quizletandroid.k;
import com.quizlet.quizletandroid.ui.joincontenttofolder.j;
import com.quizlet.remote.model.explanations.question.RemoteQuestion;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.qclass.RemoteClass;
import com.quizlet.remote.model.school.RemoteSchool;
import com.quizlet.remote.model.search.RemoteAllResultsAssociationModels;
import com.quizlet.remote.model.search.RemoteAllResultsModels;
import com.quizlet.remote.model.search.SearchAllResultsResponse;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.term.RemoteTerm;
import com.quizlet.remote.model.user.RemoteUser;
import com.quizlet.shared.httpclient.exceptions.NetworkErrorException;
import com.quizlet.shared.httpclient.f;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.core.p;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.coroutines.h;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.reflect.n;
import kotlin.u;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;
import okhttp3.H;
import okhttp3.InterfaceC5076e;
import okhttp3.InterfaceC5077f;

/* loaded from: classes2.dex */
public final class a implements com.google.firebase.crashlytics.internal.analytics.b, com.google.firebase.crashlytics.internal.analytics.a, com.quizlet.featuregate.contracts.features.a, InterfaceC5077f, com.quizlet.remote.mapper.base.a {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;

    /* JADX WARN: Multi-variable type inference failed */
    public a(i fragment, Function1 viewBindingFactory) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(fragment, "fragment");
        Intrinsics.checkNotNullParameter(viewBindingFactory, "viewBindingFactory");
        this.b = fragment;
        this.c = (C4956o) viewBindingFactory;
        fragment.getLifecycle().a(new com.onetrust.otpublishers.headless.UI.Helper.b(this));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r11v2, types: [androidx.paging.E] */
    public static final C1325l b(a aVar, C1325l c1325l, F f, F f2) {
        E e;
        E e2;
        ?? r11;
        aVar.getClass();
        D d = D.c;
        if (c1325l == null || (e = c1325l.a) == null) {
            e = d;
        }
        E e3 = f.a;
        E eK = k(e, e3, e3, f2 != null ? f2.a : null);
        if (c1325l == null || (e2 = c1325l.b) == null) {
            e2 = d;
        }
        E e4 = f2 != null ? f2.b : null;
        E e5 = f.a;
        E eK2 = k(e2, e5, f.b, e4);
        if (c1325l != null && (r11 = c1325l.c) != 0) {
            d = r11;
        }
        return new C1325l(eK, eK2, k(d, e5, f.c, f2 != null ? f2.c : null), f, f2);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00ea  */
    /* JADX WARN: Removed duplicated region for block: B:56:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /* JADX WARN: Type inference failed for: r10v12 */
    /* JADX WARN: Type inference failed for: r10v13 */
    /* JADX WARN: Type inference failed for: r10v2, types: [kotlin.jvm.functions.Function2] */
    /* JADX WARN: Type inference failed for: r10v5, types: [kotlin.jvm.functions.Function2] */
    /* JADX WARN: Type inference failed for: r10v7, types: [kotlin.jvm.functions.Function2] */
    /* JADX WARN: Type inference failed for: r11v29, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r2v0, types: [int] */
    /* JADX WARN: Type inference failed for: r2v1 */
    /* JADX WARN: Type inference failed for: r2v14 */
    /* JADX WARN: Type inference failed for: r2v15 */
    /* JADX WARN: Type inference failed for: r2v16 */
    /* JADX WARN: Type inference failed for: r2v3, types: [com.quizlet.data.repository.user.a] */
    /* JADX WARN: Type inference failed for: r2v9 */
    /* JADX WARN: Type inference failed for: r8v0, types: [com.quizlet.data.repository.user.a, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r8v1 */
    /* JADX WARN: Type inference failed for: r8v10 */
    /* JADX WARN: Type inference failed for: r8v11 */
    /* JADX WARN: Type inference failed for: r8v12 */
    /* JADX WARN: Type inference failed for: r8v3, types: [boolean] */
    /* JADX WARN: Type inference failed for: r8v5 */
    /* JADX WARN: Type inference failed for: r9v0, types: [boolean] */
    /* JADX WARN: Type inference failed for: r9v1 */
    /* JADX WARN: Type inference failed for: r9v10 */
    /* JADX WARN: Type inference failed for: r9v11 */
    /* JADX WARN: Type inference failed for: r9v12 */
    /* JADX WARN: Type inference failed for: r9v3, types: [java.util.Iterator] */
    /* JADX WARN: Type inference failed for: r9v5 */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:47:0x0111 -> B:40:0x00e4). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:49:0x0114 -> B:40:0x00e4). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object d(com.quizlet.data.repository.user.a r8, boolean r9, com.quizlet.upgrade.data.C4836d r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            Method dump skipped, instructions count: 290
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.user.a.d(com.quizlet.data.repository.user.a, boolean, com.quizlet.upgrade.data.d, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static E k(E e, E e2, E e3, E e4) {
        return e4 == null ? e3 : e instanceof C ? (((e2 instanceof D) && (e4 instanceof D)) || (e4 instanceof B)) ? e4 : e : e4;
    }

    public static HashSet p(List list, boolean z) {
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            C4117c2 c4117c2 = (C4117c2) obj;
            if (!z || c4117c2.d) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(((C4117c2) it2.next()).e);
        }
        return CollectionsKt.u0(arrayList2);
    }

    /* JADX WARN: Type inference failed for: r3v13, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.o] */
    public androidx.viewbinding.a a(i thisRef, n property) {
        Intrinsics.checkNotNullParameter(thisRef, "thisRef");
        Intrinsics.checkNotNullParameter(property, "property");
        androidx.viewbinding.a aVar = (androidx.viewbinding.a) this.d;
        if (aVar != null) {
            return aVar;
        }
        if (!((L) ((i) this.b).getViewLifecycleOwner().getLifecycle()).d.a(androidx.lifecycle.B.b)) {
            throw new IllegalStateException("Should not attempt to get bindings when Fragment views are destroyed.");
        }
        View viewRequireView = thisRef.requireView();
        Intrinsics.checkNotNullExpressionValue(viewRequireView, "thisRef.requireView()");
        androidx.viewbinding.a aVar2 = (androidx.viewbinding.a) ((C4956o) this.c).invoke(viewRequireView);
        this.d = aVar2;
        return aVar2;
    }

    public /* bridge */ /* synthetic */ Object clone() {
        switch (this.a) {
            case 6:
                a aVar = new a(((C2967b) this.b).clone());
                Iterator it2 = ((ArrayList) this.d).iterator();
                while (it2.hasNext()) {
                    ((ArrayList) aVar.d).add(((C2967b) it2.next()).clone());
                }
                return aVar;
            default:
                return super.clone();
        }
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return S.f(this, list);
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x00cc  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(long r10, long r12, com.quizlet.data.interactor.set.permissions.a r14, kotlin.coroutines.jvm.internal.c r15) {
        /*
            Method dump skipped, instructions count: 251
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.user.a.f(long, long, com.quizlet.data.interactor.set.permissions.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(long r9, boolean r11, java.util.HashSet r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            r8 = this;
            boolean r0 = r13 instanceof com.quizlet.data.interactor.set.permissions.c
            if (r0 == 0) goto L13
            r0 = r13
            com.quizlet.data.interactor.set.permissions.c r0 = (com.quizlet.data.interactor.set.permissions.c) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.data.interactor.set.permissions.c r0 = new com.quizlet.data.interactor.set.permissions.c
            r0.<init>(r8, r13)
        L18:
            java.lang.Object r13 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L36
            if (r2 != r3) goto L2e
            boolean r11 = r0.j
            com.quizlet.data.repository.user.a r9 = r0.l
            java.util.HashSet r12 = r0.k
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto Lab
        L2e:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r0.k = r12
            r0.l = r8
            r0.j = r11
            r0.o = r3
            java.lang.Object r13 = r8.b
            com.quizlet.data.repository.studysetwithcreatorinclass.g r13 = (com.quizlet.data.repository.studysetwithcreatorinclass.g) r13
            java.lang.Object r13 = r13.b
            com.quizlet.data.interactor.school.b r13 = (com.quizlet.data.interactor.school.b) r13
            java.lang.Object r13 = r13.b
            com.quizlet.data.repository.activitycenter.b r13 = (com.quizlet.data.repository.activitycenter.b) r13
            java.lang.Object r2 = r13.b
            com.quizlet.local.ormlite.models.bookmark.a r2 = (com.quizlet.local.ormlite.models.bookmark.a) r2
            java.lang.Long r4 = java.lang.Long.valueOf(r9)
            java.util.List r4 = kotlin.collections.A.b(r4)
            java.lang.String r5 = "setIds"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r5)
            java.lang.Object r6 = r2.d
            com.quizlet.data.interactor.course.a r6 = (com.quizlet.data.interactor.course.a) r6
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r5)
            com.j256.ormlite.dao.Dao r6 = r6.d()
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r5)
            java.lang.String r4 = com.google.android.gms.internal.mlkit_vision_document_scanner.A.b(r4)
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            java.lang.String r7 = "\n                SELECT * FROM group_set\n                WHERE setId IN "
            r5.<init>(r7)
            r5.append(r4)
            java.lang.String r4 = "\n                AND isDeleted = 0\n        "
            r5.append(r4)
            java.lang.String r4 = r5.toString()
            java.lang.String r4 = kotlin.text.x.c(r4)
            io.reactivex.rxjava3.internal.operators.flowable.b r4 = com.quizlet.local.ormlite.util.b.b(r6, r4)
            java.lang.Object r2 = r2.c
            com.quizlet.shared.usecase.folderstudymaterials.b r2 = (com.quizlet.shared.usecase.folderstudymaterials.b) r2
            io.reactivex.rxjava3.internal.operators.single.g r2 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z.b(r2, r4)
            androidx.compose.foundation.gestures.l1 r4 = new androidx.compose.foundation.gestures.l1
            r5 = 22
            r4.<init>(r13, r9, r5)
            io.reactivex.rxjava3.internal.operators.single.g r9 = r2.e(r4)
            java.lang.String r10 = "flatMap(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r10)
            java.lang.Object r13 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r9, r0)
            if (r13 != r1) goto Laa
            return r1
        Laa:
            r9 = r8
        Lab:
            java.util.List r13 = (java.util.List) r13
            r9.getClass()
            java.util.HashSet r9 = p(r13, r11)
            java.util.LinkedHashSet r9 = kotlin.collections.CollectionsKt.Q(r9, r12)
            boolean r9 = r9.isEmpty()
            r9 = r9 ^ r3
            java.lang.Boolean r9 = java.lang.Boolean.valueOf(r9)
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.user.a.g(long, boolean, java.util.HashSet, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.google.firebase.crashlytics.internal.analytics.b
    public void h(Bundle bundle, String str) {
        CountDownLatch countDownLatch = (CountDownLatch) this.d;
        if (countDownLatch != null && "_ae".equals(str)) {
            countDownLatch.countDown();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object i(long r5, boolean r7, java.util.HashSet r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r9 instanceof com.quizlet.data.interactor.set.permissions.d
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.data.interactor.set.permissions.d r0 = (com.quizlet.data.interactor.set.permissions.d) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.data.interactor.set.permissions.d r0 = new com.quizlet.data.interactor.set.permissions.d
            r0.<init>(r4, r9)
        L18:
            java.lang.Object r9 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            boolean r7 = r0.j
            com.quizlet.data.repository.user.a r5 = r0.l
            java.util.HashSet r8 = r0.k
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Exception -> L63
            goto L4c
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r4.b     // Catch: java.lang.Exception -> L63
            com.quizlet.data.repository.studysetwithcreatorinclass.g r9 = (com.quizlet.data.repository.studysetwithcreatorinclass.g) r9     // Catch: java.lang.Exception -> L63
            r0.k = r8     // Catch: java.lang.Exception -> L63
            r0.l = r4     // Catch: java.lang.Exception -> L63
            r0.j = r7     // Catch: java.lang.Exception -> L63
            r0.o = r3     // Catch: java.lang.Exception -> L63
            java.io.Serializable r9 = r9.j(r5, r0)     // Catch: java.lang.Exception -> L63
            if (r9 != r1) goto L4b
            return r1
        L4b:
            r5 = r4
        L4c:
            java.util.List r9 = (java.util.List) r9     // Catch: java.lang.Exception -> L63
            r5.getClass()     // Catch: java.lang.Exception -> L63
            java.util.HashSet r5 = p(r9, r7)     // Catch: java.lang.Exception -> L63
            java.util.LinkedHashSet r5 = kotlin.collections.CollectionsKt.Q(r5, r8)     // Catch: java.lang.Exception -> L63
            boolean r5 = r5.isEmpty()     // Catch: java.lang.Exception -> L63
            r5 = r5 ^ r3
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            return r5
        L63:
            java.lang.Boolean r5 = java.lang.Boolean.FALSE
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.user.a.i(long, boolean, java.util.HashSet, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.featuregate.contracts.features.a
    public boolean isEnabled() {
        try {
            return ((Boolean) ((u) this.d).getValue()).booleanValue();
        } catch (Exception e) {
            timber.log.c.a.q(e, "Unexpected error when checking growthbook feature: ".concat((String) this.b), new Object[0]);
            return false;
        }
    }

    public Object j(h hVar) {
        return Boolean.valueOf(isEnabled());
    }

    public Object l() {
        Object objRemoveLast;
        synchronized (this.c) {
            objRemoveLast = ((ArrayDeque) this.b).removeLast();
        }
        return objRemoveLast;
    }

    public void m(Function1 function1) {
        s0 s0Var;
        Object value;
        C1325l c1325l;
        do {
            s0Var = (s0) this.c;
            value = s0Var.getValue();
            C1325l c1325l2 = (C1325l) value;
            c1325l = (C1325l) function1.invoke(c1325l2);
            if (Intrinsics.b(c1325l2, c1325l)) {
                return;
            }
        } while (!s0Var.k(value, c1325l));
        if (c1325l != null) {
            Iterator it2 = ((CopyOnWriteArrayList) this.b).iterator();
            while (it2.hasNext()) {
                ((Function1) it2.next()).invoke(c1325l);
            }
        }
    }

    @Override // com.google.firebase.crashlytics.internal.analytics.a
    public void n(Bundle bundle) {
        synchronized (this.c) {
            Objects.toString(bundle);
            Log.isLoggable("FirebaseCrashlytics", 2);
            this.d = new CountDownLatch(1);
            ((com.airbnb.lottie.network.c) this.b).n(bundle);
            Log.isLoggable("FirebaseCrashlytics", 2);
            try {
                if (((CountDownLatch) this.d).await(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR, TimeUnit.MILLISECONDS)) {
                    Log.isLoggable("FirebaseCrashlytics", 2);
                } else {
                    Log.w("FirebaseCrashlytics", "Timeout exceeded while awaiting app exception callback from Analytics listener.", null);
                }
            } catch (InterruptedException unused) {
                Log.e("FirebaseCrashlytics", "Interrupted while awaiting app exception callback from Analytics listener.", null);
            }
            this.d = null;
        }
    }

    public void o(O o) {
        Object objL;
        M mN = o.N();
        InterfaceC0177p interfaceC0177p = mN instanceof androidx.camera.core.internal.c ? ((androidx.camera.core.internal.c) mN).a : null;
        if ((interfaceC0177p.g() != EnumC0175n.f && interfaceC0177p.g() != EnumC0175n.d) || interfaceC0177p.d() != EnumC0174m.e || interfaceC0177p.c() != EnumC0176o.d) {
            ((androidx.camera.camera2.internal.s0) this.d).getClass();
            o.close();
            return;
        }
        synchronized (this.c) {
            try {
                objL = ((ArrayDeque) this.b).size() >= 3 ? l() : null;
                ((ArrayDeque) this.b).addFirst(o);
            } catch (Throwable th) {
                throw th;
            }
        }
        if (((androidx.camera.camera2.internal.s0) this.d) == null || objL == null) {
            return;
        }
        ((O) objL).close();
    }

    @Override // okhttp3.InterfaceC5077f
    public void onFailure(InterfaceC5076e call, IOException e) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(e, "e");
        ((f) this.b).invoke(new com.quizlet.shared.httpclient.a(new NetworkErrorException(null, e)));
    }

    @Override // okhttp3.InterfaceC5077f
    public void onResponse(InterfaceC5076e call, H okHttpResponse) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(okHttpResponse, "okHttpResponse");
        ((f) this.c).invoke(com.quizlet.remote.kmp.a.a((com.quizlet.remote.kmp.a) this.d, okHttpResponse));
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x0051, code lost:
    
        if (r8 == r1) goto L26;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object q(boolean r6, com.quizlet.billing.subscriptions.j r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r5 = this;
            boolean r0 = r8 instanceof com.quizlet.upgrade.data.C4839g
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.upgrade.data.g r0 = (com.quizlet.upgrade.data.C4839g) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.upgrade.data.g r0 = new com.quizlet.upgrade.data.g
            r0.<init>(r5, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L36
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r8)
            return r8
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L54
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Object r8 = r5.c
            com.quizlet.billing.subscriptions.i r8 = (com.quizlet.billing.subscriptions.i) r8
            io.reactivex.rxjava3.internal.operators.maybe.h r7 = r8.a(r7)
            if (r6 == 0) goto L5a
            com.quizlet.upgrade.data.h r6 = new com.quizlet.upgrade.data.h
            r8 = 0
            r6.<init>(r7, r8)
            r0.l = r4
            r7 = 5000(0x1388, double:2.4703E-320)
            java.lang.Object r8 = kotlinx.coroutines.E.K(r7, r6, r0)
            if (r8 != r1) goto L54
            goto L62
        L54:
            kotlin.jvm.internal.Intrinsics.d(r8)
            com.quizlet.data.model.billing.a r8 = (com.quizlet.data.model.billing.a) r8
            return r8
        L5a:
            r0.l = r3
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.I1.d(r7, r0)
            if (r6 != r1) goto L63
        L62:
            return r1
        L63:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.user.a.q(boolean, com.quizlet.billing.subscriptions.j, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable r(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.set.permissions.e
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.set.permissions.e r0 = (com.quizlet.data.interactor.set.permissions.e) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.set.permissions.e r0 = new com.quizlet.data.interactor.set.permissions.e
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L43
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r4.c
            com.quizlet.data.repository.classmembership.c r7 = (com.quizlet.data.repository.classmembership.c) r7
            io.reactivex.rxjava3.internal.operators.completable.m r5 = r7.b(r5)
            r0.l = r3
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)
            if (r7 != r1) goto L43
            return r1
        L43:
            java.lang.String r5 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r5)
            java.lang.Iterable r7 = (java.lang.Iterable) r7
            java.util.ArrayList r5 = new java.util.ArrayList
            r5.<init>()
            java.util.Iterator r6 = r7.iterator()
        L53:
            boolean r7 = r6.hasNext()
            if (r7 == 0) goto L68
            java.lang.Object r7 = r6.next()
            r0 = r7
            com.quizlet.data.model.E r0 = (com.quizlet.data.model.E) r0
            boolean r0 = r0.i
            if (r0 == 0) goto L53
            r5.add(r7)
            goto L53
        L68:
            java.util.ArrayList r6 = new java.util.ArrayList
            r7 = 10
            int r7 = kotlin.collections.C.q(r5, r7)
            r6.<init>(r7)
            java.util.Iterator r5 = r5.iterator()
        L77:
            boolean r7 = r5.hasNext()
            if (r7 == 0) goto L8e
            java.lang.Object r7 = r5.next()
            com.quizlet.data.model.E r7 = (com.quizlet.data.model.E) r7
            long r0 = r7.b
            java.lang.Long r7 = new java.lang.Long
            r7.<init>(r0)
            r6.add(r7)
            goto L77
        L8e:
            java.util.HashSet r5 = kotlin.collections.CollectionsKt.u0(r6)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.user.a.r(long, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public void s(String screenName, String studyableTitle, long j, G1 studyableType, A1 a1) {
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        Intrinsics.checkNotNullParameter(studyableTitle, "studyableTitle");
        Intrinsics.checkNotNullParameter(studyableType, "studyableType");
        ((com.quizlet.infra.legacysyncengine.managers.d) this.b).a().i(new com.quizlet.quizletandroid.logging.ga.a(this, screenName, studyableTitle, Long.valueOf(j), studyableType, a1), new com.quizlet.billing.manager.d(timber.log.c.a, 7));
    }

    public void t(String screenName) {
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        ((FirebaseAnalytics) this.d).a(AbstractC3206m6.a(new Pair("screen_name", screenName), new Pair("screen_class", screenName)), "screen_view");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r10v1, types: [java.lang.Iterable] */
    /* JADX WARN: Type inference failed for: r10v5, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r1v2, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r1v3 */
    /* JADX WARN: Type inference failed for: r1v7, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r4v17, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r4v4, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r4v5 */
    /* JADX WARN: Type inference failed for: r5v5, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r5v6, types: [java.lang.Iterable] */
    /* JADX WARN: Type inference failed for: r5v8, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r6v3, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r6v4, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r6v5, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r8v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r8v1, types: [java.lang.Iterable] */
    /* JADX WARN: Type inference failed for: r8v16, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r8v2, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r8v24, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r8v3 */
    @Override // com.quizlet.remote.mapper.base.a
    /* renamed from: u, reason: merged with bridge method [inline-methods] */
    public C4172v c(SearchAllResultsResponse remote) {
        ?? arrayList;
        ?? arrayList2;
        ?? arrayList3;
        ?? arrayList4;
        ?? arrayList5;
        ?? arrayList6;
        List list;
        List list2;
        Map mapC;
        ?? arrayList7;
        Iterator it2;
        List list3;
        ArrayList arrayList8;
        Object next;
        List list4;
        List list5;
        List list6;
        Object next2;
        Iterator it3;
        Object next3;
        Intrinsics.checkNotNullParameter(remote, "remote");
        RemoteAllResultsModels remoteAllResultsModels = remote.d;
        List list7 = remote.f;
        if (list7 == null) {
            list7 = K.a;
        }
        ArrayList arrayListF = S.f((com.quizlet.quizletandroid.ui.joincontenttofolder.i) this.c, list7);
        List list8 = remoteAllResultsModels != null ? remoteAllResultsModels.e : null;
        RemoteAllResultsAssociationModels remoteAllResultsAssociationModels = remote.e;
        List list9 = remoteAllResultsAssociationModels != null ? remoteAllResultsAssociationModels.b : null;
        List list10 = remoteAllResultsModels != null ? remoteAllResultsModels.j : null;
        if (list9 != null) {
            arrayList = new ArrayList(kotlin.collections.C.q(list9, 10));
            Iterator it4 = list9.iterator();
            while (it4.hasNext()) {
                arrayList.add(com.quizlet.quizletandroid.ui.activitycenter.models.a.b((RemoteUser) it4.next()));
            }
        } else {
            arrayList = K.a;
        }
        if (list10 == null) {
            list10 = K.a;
        }
        List listE = ((j) this.d).e(list10);
        if (list8 != null) {
            arrayList2 = new ArrayList(kotlin.collections.C.q(list8, 10));
            Iterator it5 = list8.iterator();
            while (it5.hasNext()) {
                RemoteSet remoteSet = (RemoteSet) it5.next();
                Iterator it6 = arrayList.iterator();
                while (true) {
                    if (!it6.hasNext()) {
                        next2 = null;
                        break;
                    }
                    next2 = it6.next();
                    long j = ((User) next2).a;
                    Long l = remoteSet.e;
                    if (l != null && j == l.longValue()) {
                        break;
                    }
                }
                User user = (User) next2;
                Iterator it7 = ((ArrayList) listE).iterator();
                while (true) {
                    if (!it7.hasNext()) {
                        it3 = it5;
                        next3 = null;
                        break;
                    }
                    next3 = it7.next();
                    it3 = it5;
                    if (((com.quizlet.data.model.search.d) next3).a == remoteSet.a) {
                        break;
                    }
                    it5 = it3;
                }
                arrayList2.add(new C4113b2(com.quizlet.quizletandroid.ui.profile.data.b.b(remoteSet), user, (com.quizlet.data.model.search.d) next3));
                it5 = it3;
            }
        } else {
            arrayList2 = K.a;
        }
        if (remoteAllResultsModels == null || (list6 = remoteAllResultsModels.f) == null) {
            arrayList3 = K.a;
        } else {
            arrayList3 = new ArrayList(kotlin.collections.C.q(list6, 10));
            Iterator it8 = list6.iterator();
            while (it8.hasNext()) {
                arrayList3.add(((k) this.b).c((RemoteTextbook) it8.next()));
            }
        }
        if (remoteAllResultsModels == null || (list5 = remoteAllResultsModels.g) == null) {
            arrayList4 = K.a;
        } else {
            arrayList4 = new ArrayList(kotlin.collections.C.q(list5, 10));
            Iterator it9 = list5.iterator();
            while (it9.hasNext()) {
                arrayList4.add(com.quizlet.quizletandroid.managers.upgrade.a.f((RemoteQuestion) it9.next()));
            }
        }
        if (remoteAllResultsModels == null || (list4 = remoteAllResultsModels.h) == null) {
            arrayList5 = K.a;
        } else {
            arrayList5 = new ArrayList(kotlin.collections.C.q(list4, 10));
            Iterator it10 = list4.iterator();
            while (it10.hasNext()) {
                arrayList5.add(com.quizlet.quizletandroid.ui.activitycenter.models.a.b((RemoteUser) it10.next()));
            }
        }
        List list11 = arrayList5;
        List list12 = remoteAllResultsModels != null ? remoteAllResultsModels.d : null;
        List list13 = remoteAllResultsAssociationModels != null ? remoteAllResultsAssociationModels.a : null;
        if (list13 != null) {
            arrayList6 = new ArrayList(kotlin.collections.C.q(list13, 10));
            Iterator it11 = list13.iterator();
            while (it11.hasNext()) {
                arrayList6.add(com.quizlet.remote.model.school.a.a((RemoteSchool) it11.next()));
            }
        } else {
            arrayList6 = K.a;
        }
        if (list12 != null) {
            ArrayList arrayList9 = new ArrayList(kotlin.collections.C.q(list12, 10));
            Iterator it12 = list12.iterator();
            List list14 = arrayList3;
            ArrayList arrayList10 = arrayList9;
            while (it12.hasNext()) {
                RemoteClass remoteClass = (RemoteClass) it12.next();
                Iterator it13 = arrayList6.iterator();
                List list15 = list14;
                ArrayList arrayList11 = arrayList10;
                while (true) {
                    if (!it13.hasNext()) {
                        it2 = it12;
                        list3 = list15;
                        arrayList8 = arrayList11;
                        next = null;
                        break;
                    }
                    next = it13.next();
                    arrayList8 = arrayList11;
                    it2 = it12;
                    list3 = list15;
                    if (((School) next).a == remoteClass.d) {
                        break;
                    }
                    list15 = list3;
                    arrayList11 = arrayList8;
                    it12 = it2;
                }
                ArrayList arrayList12 = arrayList8;
                arrayList12.add(new C4136i1(com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a.d(remoteClass), (School) next));
                arrayList10 = arrayList12;
                list14 = list3;
                it12 = it2;
            }
            list = list14;
            list2 = arrayList10;
        } else {
            list = arrayList3;
            list2 = K.a;
        }
        List<RemoteTerm> list16 = remoteAllResultsModels != null ? remoteAllResultsModels.i : null;
        List<RemoteSet> list17 = remoteAllResultsAssociationModels != null ? remoteAllResultsAssociationModels.c : null;
        if (list17 != null) {
            int iA = U.a(kotlin.collections.C.q(list17, 10));
            if (iA < 16) {
                iA = 16;
            }
            mapC = new LinkedHashMap(iA);
            for (RemoteSet remoteSet2 : list17) {
                mapC.put(Long.valueOf(remoteSet2.a), com.quizlet.quizletandroid.ui.profile.data.b.b(remoteSet2));
            }
        } else {
            mapC = V.c();
        }
        if (list16 != null) {
            arrayList7 = new ArrayList(kotlin.collections.C.q(list16, 10));
            for (RemoteTerm remoteTerm : list16) {
                arrayList7.add(new j2(com.quizlet.quizletandroid.ui.setcreation.adapters.a.b(remoteTerm), (StudySet) mapC.get(Long.valueOf(remoteTerm.b))));
            }
        } else {
            arrayList7 = K.a;
        }
        List list18 = arrayList7;
        ArrayList arrayList13 = new ArrayList(kotlin.collections.C.q(arrayList4, 10));
        for (C0 c0 : arrayList4) {
            arrayList13.add(new C4154o1(c0.a, c0.g, null, c0.b, c0.e, c0.f, "", null));
            C4172v c4172v = c4172v;
        }
        return new C4172v(arrayList2, list, arrayList13, list11, list2, list18, arrayListF);
    }

    public Bundle v(int i, long j, String str) {
        Bundle bundle = new Bundle();
        bundle.putString("isLoggedIn", "true");
        bundle.putString("userRange", str);
        bundle.putString("selfIdentifiedUserType", String.valueOf(i));
        bundle.putString("userId", String.valueOf(j));
        bundle.putString("clientId", ((com.google.android.gms.analytics.c) this.c).a());
        return bundle;
    }

    public p w() {
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new androidx.work.impl.utils.d(this, 10), 6);
        Intrinsics.checkNotNullExpressionValue(bVar, "fromCallable(...)");
        return bVar;
    }

    public void x(F sourceLoadStates, F f) {
        Intrinsics.checkNotNullParameter(sourceLoadStates, "sourceLoadStates");
        m(new g(this, sourceLoadStates, f, 26));
    }

    public void y(String str, double d, double d2) {
        ArrayList arrayList;
        ArrayList arrayList2;
        ArrayList arrayList3;
        int i = 0;
        while (true) {
            arrayList = (ArrayList) this.b;
            int size = arrayList.size();
            arrayList2 = (ArrayList) this.c;
            arrayList3 = (ArrayList) this.d;
            if (i >= size) {
                break;
            }
            double dDoubleValue = ((Double) arrayList3.get(i)).doubleValue();
            double dDoubleValue2 = ((Double) arrayList2.get(i)).doubleValue();
            if (d < dDoubleValue || (dDoubleValue == d && d2 < dDoubleValue2)) {
                break;
            } else {
                i++;
            }
        }
        arrayList.add(i, str);
        arrayList3.add(i, Double.valueOf(d));
        arrayList2.add(i, Double.valueOf(d2));
    }

    public /* synthetic */ a(Serializable serializable, Serializable serializable2, Object obj, int i) {
        this.a = i;
        this.b = serializable;
        this.c = serializable2;
        this.d = obj;
    }

    public a(C2967b c2967b) {
        this.a = 6;
        this.b = c2967b;
        this.c = c2967b.clone();
        this.d = new ArrayList();
    }

    public a(s database, ModelIdentityProvider modelIdentityProvider, retrofit2.adapter.rxjava3.d mapper) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = modelIdentityProvider;
        this.c = mapper;
        this.d = (com.quizlet.local.ormlite.database.dao.b) database.i;
    }

    public a(com.quizlet.data.repository.studysetwithcreatorinclass.g classSetRepository, com.quizlet.data.repository.classmembership.c classMembershipRepository, com.quizlet.cache.a cache) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(classSetRepository, "classSetRepository");
        Intrinsics.checkNotNullParameter(classMembershipRepository, "classMembershipRepository");
        Intrinsics.checkNotNullParameter(cache, "cache");
        this.b = classSetRepository;
        this.c = classMembershipRepository;
        this.d = cache;
    }

    public a(com.quizlet.data.interactor.course.a groupDataSourceFactory) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(groupDataSourceFactory, "groupDataSourceFactory");
        this.b = groupDataSourceFactory;
    }

    public a(com.quizlet.data.repository.activitycenter.b factory, com.quizlet.data.connectivity.a networkStatus, org.slf4j.b logger) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = factory;
        this.c = networkStatus;
        this.d = logger;
    }

    public a(String featureName, com.quizlet.infra.contracts.growthbook.a growthBook) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(featureName, "featureName");
        Intrinsics.checkNotNullParameter(growthBook, "growthBook");
        this.b = featureName;
        this.c = growthBook;
        this.d = l.b(new com.quizlet.featuregate.growthbook.a(this, 0));
    }

    public a(com.lyft.android.scissors.b billingUserManager, com.quizlet.billing.subscriptions.i subscriptionLookup, AbstractC5040y dispatcher) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(billingUserManager, "billingUserManager");
        Intrinsics.checkNotNullParameter(subscriptionLookup, "subscriptionLookup");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = billingUserManager;
        this.c = subscriptionLookup;
        this.d = dispatcher;
    }

    public a(com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, com.google.android.gms.analytics.c gtmTracker, FirebaseAnalytics firebaseAnalytics) {
        this.a = 14;
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(gtmTracker, "gtmTracker");
        Intrinsics.checkNotNullParameter(firebaseAnalytics, "firebaseAnalytics");
        this.b = loggedInUserManager;
        this.c = gtmTracker;
        this.d = firebaseAnalytics;
    }

    public a(com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a classMapper, com.quizlet.remote.model.school.a schoolMapper, com.quizlet.quizletandroid.ui.activitycenter.models.a userMapper, com.quizlet.quizletandroid.ui.profile.data.b setMapper, com.quizlet.quizletandroid.managers.upgrade.a questionMapper, k textbookMapper, com.quizlet.quizletandroid.ui.setcreation.adapters.a termMapper, com.quizlet.quizletandroid.ui.joincontenttofolder.i shelfRankingMapper, j socialSignalsMapper) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(classMapper, "classMapper");
        Intrinsics.checkNotNullParameter(schoolMapper, "schoolMapper");
        Intrinsics.checkNotNullParameter(userMapper, "userMapper");
        Intrinsics.checkNotNullParameter(setMapper, "setMapper");
        Intrinsics.checkNotNullParameter(questionMapper, "questionMapper");
        Intrinsics.checkNotNullParameter(textbookMapper, "textbookMapper");
        Intrinsics.checkNotNullParameter(termMapper, "termMapper");
        Intrinsics.checkNotNullParameter(shelfRankingMapper, "shelfRankingMapper");
        Intrinsics.checkNotNullParameter(socialSignalsMapper, "socialSignalsMapper");
        this.b = textbookMapper;
        this.c = shelfRankingMapper;
        this.d = socialSignalsMapper;
    }

    public a(com.quizlet.data.repository.login.a _koin) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(_koin, "_koin");
        this.b = _koin;
        this.c = new ConcurrentHashMap();
        this.d = new HashMap();
    }

    public a(com.airbnb.lottie.network.c cVar) {
        this.a = 8;
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        this.c = new Object();
        this.b = cVar;
    }

    public a(com.quizlet.data.interactor.school.e setPageProgressDataSourceFactory, com.quizlet.shared.usecase.folderstudymaterials.c mapper, o scheduler) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(setPageProgressDataSourceFactory, "setPageProgressDataSourceFactory");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        Intrinsics.checkNotNullParameter(scheduler, "scheduler");
        this.b = setPageProgressDataSourceFactory;
        this.c = mapper;
        this.d = scheduler;
    }

    public a(androidx.camera.camera2.internal.s0 s0Var) {
        this.a = 1;
        this.c = new Object();
        this.b = new ArrayDeque(3);
        this.d = s0Var;
    }

    public a(int i) {
        this.a = i;
        switch (i) {
            case 3:
                this.b = new CopyOnWriteArrayList();
                s0 s0VarC = e0.c(null);
                this.c = s0VarC;
                this.d = new Z(s0VarC);
                break;
            case 4:
            default:
                this.d = new com.google.android.gms.internal.mlkit_common.u(3);
                break;
            case 5:
                this.b = new ArrayList();
                this.c = new ArrayList();
                this.d = new ArrayList();
                break;
            case 6:
                this.b = new C2967b("", 0L, null);
                this.c = new C2967b("", 0L, null);
                this.d = new ArrayList();
                break;
        }
    }

    public a(com.bumptech.glide.load.engine.l lVar, com.bumptech.glide.request.g gVar, com.bumptech.glide.load.engine.o oVar) {
        this.a = 4;
        this.d = lVar;
        this.c = gVar;
        this.b = oVar;
    }
}
