package com.google.firebase.crashlytics.internal.common;

import android.util.Log;
import android.view.View;
import androidx.camera.core.b0;
import androidx.datastore.core.InterfaceC1076h;
import androidx.glance.appwidget.protobuf.Z;
import assistantMode.refactored.types.MixedOptionMatchingQuestion;
import assistantMode.types.C1454a;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3133e5;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.android.gms.internal.mlkit_vision_camera.O2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3746v6;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.android.play.core.review.ReviewInfo;
import com.google.firebase.perf.metrics.Counter;
import com.google.firebase.perf.metrics.Trace;
import com.google.firebase.perf.session.PerfSession;
import com.google.firebase.perf.v1.B;
import com.google.firebase.perf.v1.E;
import com.google.firebase.perf.v1.z;
import com.quizlet.data.connectivity.NetworkOfflineError;
import com.quizlet.data.model.C4174v1;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBImageRef;
import com.quizlet.db.data.models.persisted.DBProgressReset;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields;
import com.quizlet.features.match.data.U;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.inapp.manager.UnknownInAppReviewException;
import com.quizlet.local.datastore.preferences.Y;
import com.quizlet.studiablemodels.MixedOptionMatchingStudiableQuestion;
import com.quizlet.studiablemodels.StudiableQuestion;
import com.quizlet.uicommon.ui.common.dialogs.info.InfoModalFragment;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class j implements com.google.android.gms.tasks.e, OnCompleteListener, io.reactivex.rxjava3.functions.b, io.reactivex.rxjava3.functions.h, dagger.android.b {
    public final /* synthetic */ int a;
    public final Object b;

    public j() {
        this.a = 3;
        this.b = new int[2];
    }

    public static Object k(Object obj) {
        Throwable thA = kotlin.r.a(obj);
        if (thA != null) {
            if (AbstractC3746v6.b(thA)) {
                thA = new NetworkOfflineError(0);
            }
            return Z.b(thA);
        }
        C4174v1 c4174v1 = (C4174v1) obj;
        int size = !(c4174v1.b instanceof kotlin.q) ? c4174v1.a.size() : 0;
        int size2 = !(c4174v1.d instanceof kotlin.q) ? c4174v1.c.size() : 0;
        return new com.quizlet.features.folders.viewmodel.usecases.d(size > 0, size2 > 0, size + size2);
    }

    public JSONObject a(View view) {
        if (view == null) {
            return com.iab.omid.library.amazon.utils.b.a(0, 0, 0, 0);
        }
        int width = view.getWidth();
        int height = view.getHeight();
        int[] iArr = (int[]) this.b;
        view.getLocationOnScreen(iArr);
        return com.iab.omid.library.amazon.utils.b.a(iArr[0], iArr[1], width, height);
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        Intrinsics.checkNotNullParameter((Unit) obj, "<unused var>");
        Intrinsics.checkNotNullParameter((Unit) obj2, "<unused var>");
        return ((com.quizlet.billing.manager.f) this.b).d;
    }

    public E b() {
        List listUnmodifiableList;
        B bP = E.P();
        bP.q(((Trace) this.b).d);
        bP.o(((Trace) this.b).k.a);
        Trace trace = (Trace) this.b;
        bP.p(trace.k.b(trace.l));
        for (Counter counter : ((Trace) this.b).e.values()) {
            bP.n(counter.b.get(), counter.a);
        }
        ArrayList arrayList = ((Trace) this.b).h;
        if (!arrayList.isEmpty()) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                bP.m(new j((Trace) it2.next(), 1).b());
            }
        }
        Map<String, String> attributes = ((Trace) this.b).getAttributes();
        bP.k();
        E.A((E) bP.b).putAll(attributes);
        Trace trace2 = (Trace) this.b;
        synchronized (trace2.g) {
            try {
                ArrayList arrayList2 = new ArrayList();
                for (PerfSession perfSession : trace2.g) {
                    if (perfSession != null) {
                        arrayList2.add(perfSession);
                    }
                }
                listUnmodifiableList = Collections.unmodifiableList(arrayList2);
            } catch (Throwable th) {
                throw th;
            }
        }
        z[] zVarArrB = PerfSession.b(listUnmodifiableList);
        if (zVarArrB != null) {
            List listAsList = Arrays.asList(zVarArrB);
            bP.k();
            E.C((E) bP.b, listAsList);
        }
        return (E) bP.h();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object c(java.lang.String r5, com.quizlet.generated.enums.y1 r6, java.lang.Long r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r4 = this;
            boolean r0 = r8 instanceof com.quizlet.data.repository.foldertoadd.a
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.data.repository.foldertoadd.a r0 = (com.quizlet.data.repository.foldertoadd.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.repository.foldertoadd.a r0 = new com.quizlet.data.repository.foldertoadd.a
            r0.<init>(r4, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r8)
            kotlin.r r8 = (kotlin.r) r8
            java.lang.Object r5 = r8.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.l = r3
            java.lang.Object r8 = r4.b
            com.quizlet.data.repository.searchexplanations.c r8 = (com.quizlet.data.repository.searchexplanations.c) r8
            java.lang.Object r5 = r8.g(r5, r6, r7, r0)
            if (r5 != r1) goto L43
            return r1
        L43:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.common.j.c(java.lang.String, com.quizlet.generated.enums.y1, java.lang.Long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // dagger.android.b
    public void d(Object obj) {
        ((InfoModalFragment) obj).q = ((com.quizlet.quizletandroid.u) this.b).w();
    }

    public Object e(long j, kotlin.coroutines.jvm.internal.c cVar) {
        com.lyft.android.scissors.b bVar = (com.lyft.android.scissors.b) this.b;
        String str = String.format("user_onboarding_session_count_%s", Arrays.copyOf(new Object[]{new Long(j)}, 1));
        Intrinsics.checkNotNullExpressionValue(str, "format(...)");
        Object objD = S6.d((InterfaceC1076h) bVar.b, new Y(R6.c(str), null), cVar);
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objD != aVar) {
            objD = Unit.a;
        }
        return objD == aVar ? objD : Unit.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable f(java.lang.String r11, kotlin.coroutines.jvm.internal.c r12) throws com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.EmptyQueryException {
        /*
            r10 = this;
            boolean r0 = r12 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.k
            if (r0 == 0) goto L13
            r0 = r12
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.k r0 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.k) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.k r0 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.k
            r0.<init>(r10, r12)
        L18:
            java.lang.Object r12 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L38
            if (r2 != r3) goto L30
            java.lang.String r11 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            goto L52
        L29:
            r0 = move-exception
            r11 = r0
            goto La3
        L2d:
            r3 = r11
            goto Laa
        L30:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            int r12 = r11.length()     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            if (r12 == 0) goto L9d
            java.lang.Object r12 = r10.b     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            com.onetrust.otpublishers.headless.UI.fragment.q r12 = (com.onetrust.otpublishers.headless.UI.fragment.q) r12     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            r0.j = r11     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            r0.m = r3     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            r2 = 20
            java.lang.Object r12 = r12.m(r11, r2, r0)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            if (r12 != r1) goto L52
            return r1
        L52:
            com.quizlet.data.model.x1 r12 = (com.quizlet.data.model.C4180x1) r12     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            java.util.List r0 = r12.a     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            java.util.ArrayList r1 = new java.util.ArrayList     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            r2 = 10
            int r2 = kotlin.collections.C.q(r0, r2)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            r1.<init>(r2)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            java.util.Iterator r0 = r0.iterator()     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
        L65:
            boolean r2 = r0.hasNext()     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            if (r2 == 0) goto L9a
            java.lang.Object r2 = r0.next()     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            com.quizlet.data.model.School r2 = (com.quizlet.data.model.School) r2     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e r3 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            long r4 = r2.a     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            java.lang.String r6 = r2.i     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            java.lang.String r7 = r2.b     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            java.lang.String r2 = r2.j     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            java.lang.StringBuilder r8 = new java.lang.StringBuilder     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            r8.<init>()     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            r8.append(r7)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            java.lang.String r7 = ", "
            r8.append(r7)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            r8.append(r2)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            java.lang.String r7 = r8.toString()     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            java.lang.String r8 = r12.b     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            r9 = 24
            r3.<init>(r4, r6, r7, r8, r9)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            r1.add(r3)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            goto L65
        L9a:
            kotlin.p r11 = kotlin.r.b     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            return r1
        L9d:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.EmptyQueryException r12 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.EmptyQueryException     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            r12.<init>()     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
            throw r12     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.school.exceptions.SchoolNotFoundException -> L2d
        La3:
            kotlin.p r12 = kotlin.r.b
            kotlin.q r11 = androidx.glance.appwidget.protobuf.Z.b(r11)
            goto Lc3
        Laa:
            kotlin.p r11 = kotlin.r.b
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.NoSchoolException r11 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.NoSchoolException
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e r0 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.d r12 = com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.d.a
            java.lang.String r4 = ""
            r5 = 0
            r1 = -1
            r6 = 48
            r0.<init>(r1, r3, r4, r5, r6)
            r11.<init>(r0)
            kotlin.q r11 = androidx.glance.appwidget.protobuf.Z.b(r11)
        Lc3:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.common.j.f(java.lang.String, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    @Override // com.google.android.gms.tasks.e
    public Task g(Object obj) {
        if (((com.google.firebase.crashlytics.internal.settings.a) obj) == null) {
            Log.w("FirebaseCrashlytics", "Received null app settings, cannot send reports at crash time.", null);
            return S3.i(null);
        }
        m mVar = ((k) this.b).e;
        return S3.j(Arrays.asList(m.a(mVar), mVar.m.n(null, mVar.e.a)));
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object h(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.data.interactor.achievements.n
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.interactor.achievements.n r0 = (com.quizlet.data.interactor.achievements.n) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.achievements.n r0 = new com.quizlet.data.interactor.achievements.n
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            java.lang.String r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L43
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.m = r3
            java.lang.Object r6 = r4.b
            com.quizlet.data.repository.achievements.h r6 = (com.quizlet.data.repository.achievements.h) r6
            java.lang.Object r6 = r6.b(r0)
            if (r6 != r1) goto L43
            return r1
        L43:
            com.quizlet.data.model.k r6 = (com.quizlet.data.model.AbstractC4140k) r6
            boolean r0 = r6 instanceof com.quizlet.data.model.C4131h
            if (r0 == 0) goto L6f
            com.quizlet.data.model.h r6 = (com.quizlet.data.model.C4131h) r6
            java.util.ArrayList r6 = r6.a
            java.util.Iterator r6 = r6.iterator()
        L51:
            boolean r0 = r6.hasNext()
            if (r0 == 0) goto L67
            java.lang.Object r0 = r6.next()
            r1 = r0
            com.quizlet.data.model.a r1 = (com.quizlet.data.model.C4106a) r1
            java.lang.String r1 = r1.a
            boolean r1 = r1.equals(r5)
            if (r1 == 0) goto L51
            goto L68
        L67:
            r0 = 0
        L68:
            com.quizlet.data.model.a r0 = (com.quizlet.data.model.C4106a) r0
            if (r0 == 0) goto L6f
            kotlin.p r5 = kotlin.r.b
            return r0
        L6f:
            kotlin.p r5 = kotlin.r.b
            java.lang.Exception r5 = new java.lang.Exception
            java.lang.String r6 = "Badge not found"
            r5.<init>(r6)
            kotlin.q r5 = androidx.glance.appwidget.protobuf.Z.b(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.common.j.h(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object i(com.quizlet.data.model.I1 r5, java.util.ArrayList r6, kotlin.collections.K r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r4 = this;
            boolean r0 = r8 instanceof com.quizlet.features.folders.viewmodel.usecases.q
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.features.folders.viewmodel.usecases.q r0 = (com.quizlet.features.folders.viewmodel.usecases.q) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.folders.viewmodel.usecases.q r0 = new com.quizlet.features.folders.viewmodel.usecases.q
            r0.<init>(r4, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            com.google.firebase.crashlytics.internal.common.j r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            kotlin.r r8 = (kotlin.r) r8
            java.lang.Object r6 = r8.a
            goto L48
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r4
            r0.m = r3
            java.lang.Object r8 = r4.b
            com.quizlet.data.interactor.folderstudymaterial.z r8 = (com.quizlet.data.interactor.folderstudymaterial.z) r8
            java.lang.Object r6 = r8.b(r5, r6, r7, r0)
            if (r6 != r1) goto L47
            return r1
        L47:
            r5 = r4
        L48:
            r5.getClass()
            java.lang.Object r5 = k(r6)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.common.j.i(com.quizlet.data.model.I1, java.util.ArrayList, kotlin.collections.K, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object j(long r8, java.util.List r10, kotlinx.collections.immutable.b r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            r7 = this;
            boolean r0 = r12 instanceof com.quizlet.features.folders.viewmodel.usecases.r
            if (r0 == 0) goto L14
            r0 = r12
            com.quizlet.features.folders.viewmodel.usecases.r r0 = (com.quizlet.features.folders.viewmodel.usecases.r) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.m = r1
        L12:
            r6 = r0
            goto L1a
        L14:
            com.quizlet.features.folders.viewmodel.usecases.r r0 = new com.quizlet.features.folders.viewmodel.usecases.r
            r0.<init>(r7, r12)
            goto L12
        L1a:
            java.lang.Object r12 = r6.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.m
            r2 = 1
            if (r1 == 0) goto L37
            if (r1 != r2) goto L2f
            com.google.firebase.crashlytics.internal.common.j r8 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            kotlin.r r12 = (kotlin.r) r12
            java.lang.Object r9 = r12.a
            goto L54
        L2f:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            java.util.ArrayList r4 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3097a5.c(r10)
            java.util.ArrayList r5 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3097a5.c(r11)
            r6.j = r7
            r6.m = r2
            java.lang.Object r10 = r7.b
            r1 = r10
            com.quizlet.data.interactor.folderstudymaterial.z r1 = (com.quizlet.data.interactor.folderstudymaterial.z) r1
            r2 = r8
            java.lang.Object r9 = r1.c(r2, r4, r5, r6)
            if (r9 != r0) goto L53
            return r0
        L53:
            r8 = r7
        L54:
            r8.getClass()
            java.lang.Object r8 = k(r9)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.common.j.j(long, java.util.List, kotlinx.collections.immutable.b, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.google.android.gms.tasks.OnCompleteListener
    public void onComplete(Task task) {
        Object obj = this.b;
        switch (this.a) {
            case 2:
                com.quizlet.data.repository.widget.b bVar = com.google.mlkit.vision.camera.a.l;
                ((b0) obj).close();
                break;
            default:
                Intrinsics.checkNotNullParameter(task, "task");
                C5028l c5028l = (C5028l) obj;
                if (task.l() && task.h() != null) {
                    Object objH = task.h();
                    Intrinsics.checkNotNullExpressionValue(objH, "getResult(...)");
                    com.quizlet.inapp.model.a aVar = new com.quizlet.inapp.model.a((ReviewInfo) objH);
                    kotlin.p pVar = kotlin.r.b;
                    c5028l.resumeWith(aVar);
                    break;
                } else {
                    Exception excG = task.g();
                    if (excG == null) {
                        excG = new UnknownInAppReviewException();
                    }
                    kotlin.p pVar2 = kotlin.r.b;
                    c5028l.resumeWith(Z.b(excG));
                    break;
                }
                break;
        }
    }

    public /* synthetic */ j(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public j(C3 practiceTestsRepository) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(practiceTestsRepository, "practiceTestsRepository");
        this.b = practiceTestsRepository;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        assistantMode.enums.m mVar;
        List listC;
        switch (this.a) {
            case 11:
                List it2 = (List) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return ((com.quizlet.local.ormlite.models.bookmark.a) ((com.quizlet.data.repository.folder.i) this.b).a.b).a(it2);
            case 12:
            case 15:
            case 16:
            case 19:
            case 21:
            case EventType.SUBS /* 25 */:
            case EventType.CDN /* 26 */:
            default:
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(list, "list");
                return list.size() == ((com.quizlet.quizletandroid.data.management.a) this.b).a.getNumTerms() ? io.reactivex.rxjava3.core.g.c(list) : io.reactivex.rxjava3.internal.operators.maybe.f.a;
            case 13:
                Throwable error = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error, "error");
                ((org.slf4j.b) ((com.quizlet.data.repository.progress.b) this.b).c).p("Network error trying to fetch ProgressReset", error.getMessage());
                return io.reactivex.rxjava3.internal.operators.observable.E.a;
            case 14:
                Throwable e = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e, "e");
                ((org.slf4j.b) ((com.quizlet.data.repository.user.a) this.b).d).j("no cached object", e);
                return io.reactivex.rxjava3.internal.operators.observable.E.a;
            case 17:
                U data = (U) obj;
                Intrinsics.checkNotNullParameter(data, "data");
                com.quizlet.features.match.studyengine.b bVar = (com.quizlet.features.match.studyengine.b) this.b;
                bVar.e.clear();
                ArrayList arrayList = bVar.e;
                List<DBDiagramShape> list2 = data.b;
                ArrayList arrayList2 = new ArrayList(C.q(list2, 10));
                for (DBDiagramShape dBDiagramShape : list2) {
                    Intrinsics.checkNotNullParameter(dBDiagramShape, "<this>");
                    long setId = dBDiagramShape.getSetId();
                    String shape = dBDiagramShape.getShape();
                    Intrinsics.checkNotNullExpressionValue(shape, "getShape(...)");
                    arrayList2.add(new assistantMode.types.h(setId, dBDiagramShape.getTermId(), shape));
                }
                arrayList.addAll(arrayList2);
                androidx.work.impl.model.e eVar = new androidx.work.impl.model.e(data.e);
                bVar.b = eVar;
                assistantMode.enums.m promptSide = data.f;
                Intrinsics.checkNotNullParameter(promptSide, "promptSide");
                assistantMode.enums.m answerSide = data.g;
                Intrinsics.checkNotNullParameter(answerSide, "answerSide");
                assistantMode.utils.h hVar = (assistantMode.utils.h) eVar.b;
                List list3 = hVar.a;
                ArrayList arrayList3 = new ArrayList();
                for (Object obj2 : list3) {
                    C1454a c1454a = (C1454a) obj2;
                    assistantMode.enums.m mVar2 = assistantMode.enums.m.d;
                    if (promptSide != mVar2 || c1454a.e(promptSide)) {
                        if (answerSide != mVar2 || c1454a.e(answerSide)) {
                            arrayList3.add(obj2);
                        }
                    }
                }
                if (arrayList3.isEmpty()) {
                    mVar = answerSide;
                    listC = K.a;
                } else {
                    C1454a c1454a2 = (C1454a) CollectionsKt.f0(arrayList3, kotlin.random.e.a);
                    mVar = answerSide;
                    listC = A.c(CollectionsKt.c0(assistantMode.utils.g.l(A.c(arrayList3), 5, true, true, c1454a2, promptSide, answerSide, true), A.b(c1454a2)));
                }
                Q2 q2B = O2.b(assistantMode.enums.k.k, new assistantMode.types.n(listC, promptSide, mVar), hVar, false);
                eVar.c = (assistantMode.grading.c) q2B.c();
                assistantMode.refactored.types.d dVarD = q2B.d();
                Intrinsics.e(dVarD, "null cannot be cast to non-null type assistantMode.refactored.types.MixedOptionMatchingQuestion");
                MixedOptionMatchingQuestion mixedOptionMatchingQuestion = (MixedOptionMatchingQuestion) dVarD;
                List<DBDiagramShape> list4 = data.b;
                ArrayList arrayList4 = new ArrayList(C.q(list4, 10));
                for (DBDiagramShape dBDiagramShape2 : list4) {
                    Intrinsics.checkNotNullParameter(dBDiagramShape2, "<this>");
                    long setId2 = dBDiagramShape2.getSetId();
                    String shape2 = dBDiagramShape2.getShape();
                    Intrinsics.checkNotNullExpressionValue(shape2, "getShape(...)");
                    arrayList4.add(new assistantMode.types.h(setId2, dBDiagramShape2.getTermId(), shape2));
                }
                List list5 = data.c;
                ArrayList arrayList5 = new ArrayList(C.q(list5, 10));
                Iterator it3 = list5.iterator();
                while (it3.hasNext()) {
                    DBImageRef dBImageRef = (DBImageRef) it3.next();
                    Intrinsics.checkNotNullParameter(dBImageRef, "<this>");
                    DBImage image = dBImageRef.getImage();
                    Intrinsics.checkNotNullExpressionValue(image, "getImage(...)");
                    Intrinsics.checkNotNullParameter(image, "<this>");
                    long id = image.getId();
                    String mediumUrl = image.getMediumUrl();
                    String str = mediumUrl == null ? "" : mediumUrl;
                    String smallUrl = image.getSmallUrl();
                    String str2 = smallUrl == null ? "" : smallUrl;
                    String squareUrl = image.getSquareUrl();
                    String str3 = squareUrl == null ? "" : squareUrl;
                    String serverMediumUrl = image.getServerMediumUrl();
                    String str4 = serverMediumUrl == null ? "" : serverMediumUrl;
                    String serverSmallUrl = image.getServerSmallUrl();
                    String str5 = serverSmallUrl == null ? "" : serverSmallUrl;
                    String serverSquareUrl = image.getServerSquareUrl();
                    String str6 = serverSquareUrl == null ? "" : serverSquareUrl;
                    String code = image.getCode();
                    Intrinsics.checkNotNullExpressionValue(code, "getCode(...)");
                    long jIntValue = image.getHeight().intValue();
                    long jIntValue2 = image.getWidth().intValue();
                    Long personId = image.getPersonId();
                    Iterator it4 = it3;
                    Intrinsics.checkNotNullExpressionValue(personId, "getPersonId(...)");
                    long jLongValue = personId.longValue();
                    Long timestamp = image.getTimestamp();
                    Intrinsics.checkNotNullExpressionValue(timestamp, "getTimestamp(...)");
                    arrayList5.add(new assistantMode.types.k(str, str2, str3, str4, str5, str6, code, jIntValue, id, image.getLastModified(), jLongValue, timestamp.longValue(), jIntValue2));
                    it3 = it4;
                }
                StudiableQuestion studiableQuestionC = AbstractC3133e5.c(mixedOptionMatchingQuestion, arrayList4, arrayList5);
                if (studiableQuestionC instanceof MixedOptionMatchingStudiableQuestion) {
                    return (MixedOptionMatchingStudiableQuestion) studiableQuestionC;
                }
                throw new IllegalArgumentException(android.support.v4.media.session.a.B("Invalid question type. Expecting (MixedOptionMatchingStudiableQuestion) but was (", studiableQuestionC.getClass().getSimpleName(), ")").toString());
            case 18:
                com.quizlet.infra.legacysyncengine.features.properties.d studySetProperties = (com.quizlet.infra.legacysyncengine.features.properties.d) obj;
                Intrinsics.checkNotNullParameter(studySetProperties, "studySetProperties");
                P p = (P) this.b;
                return p.y.o(p.d, studySetProperties);
            case 20:
                List it5 = (List) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                return new Pair((DBStudySet) this.b, it5);
            case EventType.WINDOW_STATE /* 22 */:
                List modelsWithIds = (List) obj;
                Intrinsics.checkNotNullParameter(modelsWithIds, "modelsWithIds");
                com.quizlet.local.ormlite.models.bookmark.a aVar = (com.quizlet.local.ormlite.models.bookmark.a) this.b;
                return new io.reactivex.rxjava3.internal.operators.completable.m(((com.google.android.material.floatingactionbutton.c) aVar.d).f(modelsWithIds), null, Boolean.TRUE, 0).g(new com.quizlet.data.repository.widget.b(modelsWithIds, false, aVar, 22));
            case EventType.AUDIO /* 23 */:
                DBProgressReset model = (DBProgressReset) obj;
                Intrinsics.checkNotNullParameter(model, "modelWithId");
                com.google.firebase.crashlytics.internal.settings.b bVar2 = (com.google.firebase.crashlytics.internal.settings.b) ((com.quizlet.data.repository.folderwithcreator.e) this.b).b;
                Intrinsics.checkNotNullParameter(model, "model");
                return bVar2.f(A.b(model));
            case EventType.VIDEO /* 24 */:
                List it6 = (List) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                return ((com.quizlet.local.ormlite.util.c) this.b).g(it6);
            case 27:
                List p0 = (List) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                com.google.android.datatransport.cct.internal.s sVar = (com.google.android.datatransport.cct.internal.s) this.b;
                sVar.getClass();
                com.quizlet.quizletandroid.data.management.a aVar2 = (com.quizlet.quizletandroid.data.management.a) CollectionsKt.firstOrNull(p0);
                if (aVar2 != null) {
                    ArrayList arrayList6 = new ArrayList(C.q(p0, 10));
                    Iterator it7 = p0.iterator();
                    while (it7.hasNext()) {
                        arrayList6.add(Long.valueOf(((com.quizlet.quizletandroid.data.management.a) it7.next()).a.getId()));
                    }
                    Set setA0 = CollectionsKt.A0(arrayList6);
                    com.quizlet.infra.legacysyncengine.orm.b bVar3 = new com.quizlet.infra.legacysyncengine.orm.b(Models.USER_STUDYABLE);
                    bVar3.c(DBUserStudyableFields.SET, setA0, null);
                    bVar3.b(Long.valueOf(aVar2.c), DBUserStudyableFields.PERSON);
                    com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar3.a();
                    Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
                    io.reactivex.rxjava3.internal.operators.single.g gVarG = sVar.o(aVarA).g(new com.google.android.gms.tasks.n(p0, 4));
                    Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                    return gVarG;
                }
                io.reactivex.rxjava3.internal.operators.flowable.b bVarF = io.reactivex.rxjava3.core.p.f(p0);
                Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
                return bVarF;
        }
    }

    public j(com.lyft.android.scissors.b preferencesRepository) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(preferencesRepository, "preferencesRepository");
        this.b = preferencesRepository;
    }

    public j(com.quizlet.cache.a cache) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(cache, "cache");
        this.b = cache;
    }

    public j(j libraryPreferencesDataStore) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(libraryPreferencesDataStore, "libraryPreferencesDataStore");
        this.b = libraryPreferencesDataStore;
    }

    public j(com.onetrust.otpublishers.headless.UI.fragment.q searchSchoolsUseCase) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(searchSchoolsUseCase, "searchSchoolsUseCase");
        this.b = searchSchoolsUseCase;
    }

    public j(io.ktor.client.plugins.api.d repository) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public j(com.quizlet.remote.model.user.emailconfirmation.c repository) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public j(com.quizlet.data.repository.achievements.h repository) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public j(com.quizlet.infra.legacysyncengine.features.properties.d studySetProperties, com.quizlet.local.ormlite.models.set.a localStudySetMapper, assistantMode.utils.studiableMetadata.b localUserMapper) {
        this.a = 26;
        Intrinsics.checkNotNullParameter(studySetProperties, "studySetProperties");
        Intrinsics.checkNotNullParameter(localStudySetMapper, "localStudySetMapper");
        Intrinsics.checkNotNullParameter(localUserMapper, "localUserMapper");
        this.b = studySetProperties;
    }

    public j(com.quizlet.data.interactor.folderstudymaterial.z saveStudyMaterialToFolderUseCase) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(saveStudyMaterialToFolderUseCase, "saveStudyMaterialToFolderUseCase");
        this.b = saveStudyMaterialToFolderUseCase;
    }

    public j(com.quizlet.data.repository.searchexplanations.c folderToAddMaterialDataStore) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(folderToAddMaterialDataStore, "folderToAddMaterialDataStore");
        this.b = folderToAddMaterialDataStore;
    }

    public j(InterfaceC1076h dataStore) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.b = dataStore;
    }

    public j(k kVar, String str) {
        this.a = 0;
        this.b = kVar;
    }
}
