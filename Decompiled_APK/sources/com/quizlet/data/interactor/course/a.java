package com.quizlet.data.interactor.course;

import android.content.Intent;
import androidx.camera.camera2.internal.c0;
import androidx.datastore.core.InterfaceC1076h;
import androidx.work.impl.model.l;
import com.appsflyer.AppsFlyerLib;
import com.braze.Braze;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.A4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3770y6;
import com.j256.ormlite.dao.Dao;
import com.onetrust.otpublishers.headless.Public.OTCallback;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;
import com.quizlet.data.connectivity.NetworkOfflineError;
import com.quizlet.data.model.C4132h0;
import com.quizlet.data.model.CreatedFolder;
import com.quizlet.data.model.User;
import com.quizlet.data.repository.folder.i;
import com.quizlet.data.repository.metering.j;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.persisted.DBOfflineEntity;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.features.match.data.Q;
import com.quizlet.generated.enums.EnumC4513q0;
import com.quizlet.generated.enums.G1;
import com.quizlet.learn.data.C4537b;
import com.quizlet.learn.viewmodel.G;
import com.quizlet.quizletandroid.ui.RootActivity;
import com.quizlet.quizletandroid.ui.common.ads.prebid.n;
import com.quizlet.quizletandroid.ui.deeplinkinterstitial.DeepLinkInterstitialActivity;
import io.reactivex.rxjava3.internal.operators.completable.m;
import java.io.File;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import okhttp3.A;

/* loaded from: classes2.dex */
public final class a implements io.reactivex.rxjava3.functions.h, OTCallback, com.quizlet.local.ormlite.database.b, io.reactivex.rxjava3.functions.b, com.quizlet.analytics.marketing.b {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.quizlet.analytics.marketing.b
    public void a(com.quizlet.analytics.marketing.a deepLinkData) {
        Intrinsics.checkNotNullParameter(deepLinkData, "deepLinkData");
        RootActivity rootActivity = (RootActivity) ((c0) this.b).g;
        if (rootActivity == null) {
            Intrinsics.m("rootView");
            throw null;
        }
        String canonicalUrl = deepLinkData.a;
        Intrinsics.checkNotNullParameter(canonicalUrl, "canonicalUrl");
        String str = DeepLinkInterstitialActivity.s;
        rootActivity.C(new Intent[]{A4.b(rootActivity, canonicalUrl)});
        AppsFlyerLib.getInstance().subscribeForDeepLink(null);
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object t, Object u) {
        switch (this.a) {
            case 20:
                Intrinsics.checkNotNullExpressionValue(t, "t");
                Intrinsics.checkNotNullExpressionValue(u, "u");
                List<CreatedFolder> list = (List) t;
                ((com.quizlet.local.ormlite.models.bookmark.a) this.b).getClass();
                ArrayList arrayListJ = CollectionsKt.J((List) u);
                int iA = U.a(C.q(arrayListJ, 10));
                if (iA < 16) {
                    iA = 16;
                }
                LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
                Iterator it2 = arrayListJ.iterator();
                while (it2.hasNext()) {
                    Object next = it2.next();
                    linkedHashMap.put(Long.valueOf(((User) next).a), next);
                }
                ArrayList arrayList = new ArrayList(C.q(list, 10));
                for (CreatedFolder createdFolder : list) {
                    arrayList.add(new C4132h0(createdFolder, (User) linkedHashMap.get(Long.valueOf(createdFolder.h()))));
                }
                return arrayList;
            default:
                Intrinsics.checkNotNullExpressionValue(t, "t");
                Intrinsics.checkNotNullExpressionValue(u, "u");
                List list2 = (List) u;
                List list3 = (List) t;
                Intrinsics.d(list3);
                Intrinsics.d(list2);
                return com.quizlet.local.ormlite.models.studysetwithcreator.a.b((com.quizlet.local.ormlite.models.studysetwithcreator.a) this.b, list3, list2);
        }
    }

    @Override // com.quizlet.analytics.marketing.b
    public void b(String errorMessage) {
        Intrinsics.checkNotNullParameter(errorMessage, "errorMessage");
        timber.log.c.a.a(errorMessage, new Object[0]);
        RootActivity rootActivity = (RootActivity) ((c0) this.b).g;
        if (rootActivity != null) {
            rootActivity.y();
        } else {
            Intrinsics.m("rootView");
            throw null;
        }
    }

    public io.reactivex.rxjava3.internal.operators.maybe.h c(File file, String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(file, "file");
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.activitycenter.a(url, 4), 4);
        Intrinsics.checkNotNullExpressionValue(bVar, "defer(...)");
        io.reactivex.rxjava3.internal.operators.maybe.h hVar = new io.reactivex.rxjava3.internal.operators.maybe.h(3, bVar.e(new com.quizlet.login.authentication.login.a((A) this.b, 5)), new l(this, false, file, 26));
        Intrinsics.checkNotNullExpressionValue(hVar, "flatMapMaybe(...)");
        return hVar;
    }

    public Dao d() {
        Object value = ((u) this.b).getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (Dao) value;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object e(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.features.setpage.termlist.usecase.a
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.setpage.termlist.usecase.a r0 = (com.quizlet.features.setpage.termlist.usecase.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.setpage.termlist.usecase.a r0 = new com.quizlet.features.setpage.termlist.usecase.a
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L3f
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.l = r3
            java.lang.Object r7 = r4.b
            com.google.mlkit.vision.documentscanner.internal.c r7 = (com.google.mlkit.vision.documentscanner.internal.c) r7
            java.lang.Enum r7 = r7.k(r5, r0)
            if (r7 != r1) goto L3f
            return r1
        L3f:
            androidx.datastore.core.t r5 = new androidx.datastore.core.t
            r6 = 10
            r5.<init>(r7, r6)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.course.a.e(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.local.ormlite.database.b
    public io.reactivex.rxjava3.internal.operators.completable.c f(List models) {
        Intrinsics.checkNotNullParameter(models, "models");
        return com.quizlet.local.ormlite.util.b.a(d(), models);
    }

    public Object g(String str, int i, EnumC4513q0 enumC4513q0, Long l, int i2, ArrayList arrayList, kotlin.coroutines.jvm.internal.c cVar) {
        C3 c3 = (C3) this.b;
        return E.J((AbstractC5040y) c3.b, new com.quizlet.remote.model.practicetests.b(c3, str, i, arrayList, i2, enumC4513q0, l, null), cVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object h(long r5, java.util.List r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r4 = this;
            boolean r0 = r8 instanceof com.quizlet.data.interactor.folder.i
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.data.interactor.folder.i r0 = (com.quizlet.data.interactor.folder.i) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folder.i r0 = new com.quizlet.data.interactor.folder.i
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
            goto L43
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.l = r3
            java.lang.Object r8 = r4.b
            com.quizlet.data.repository.folder.i r8 = (com.quizlet.data.repository.folder.i) r8
            java.lang.Object r5 = r8.c(r5, r7, r0)
            if (r5 != r1) goto L43
            return r1
        L43:
            kotlin.p r6 = kotlin.r.b
            boolean r6 = r5 instanceof kotlin.q
            if (r6 != 0) goto L67
            java.util.List r5 = (java.util.List) r5
            java.util.ArrayList r6 = new java.util.ArrayList
            r6.<init>()
            java.util.Iterator r5 = r5.iterator()
        L54:
            boolean r7 = r5.hasNext()
            if (r7 == 0) goto L66
            java.lang.Object r7 = r5.next()
            boolean r8 = r7 instanceof com.quizlet.data.model.CreatedFolder
            if (r8 == 0) goto L54
            r6.add(r7)
            goto L54
        L66:
            return r6
        L67:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.course.a.h(long, java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object i(int r5, com.quizlet.generated.enums.Q0 r6, java.lang.String r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r4 = this;
            boolean r0 = r8 instanceof com.quizlet.data.interactor.report.a
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.data.interactor.report.a r0 = (com.quizlet.data.interactor.report.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.report.a r0 = new com.quizlet.data.interactor.report.a
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
            int r6 = r6.a()
            r0.l = r3
            java.lang.Object r8 = r4.b
            com.quizlet.remote.model.report.c r8 = (com.quizlet.remote.model.report.c) r8
            java.lang.Object r5 = r8.c(r5, r6, r7, r0)
            if (r5 != r1) goto L47
            return r1
        L47:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.course.a.i(int, com.quizlet.generated.enums.Q0, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void j(String str, String str2, String str3, boolean z) {
        ((EventLogger) this.b).r(str3, str, str2, z);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object k(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.local.datastore.preferences.j0
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.local.datastore.preferences.j0 r0 = (com.quizlet.local.datastore.preferences.j0) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.j0 r0 = new com.quizlet.local.datastore.preferences.j0
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.datastore.preferences.core.f r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L50
        L29:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.String r6 = "show_delayed_upsell"
            androidx.datastore.preferences.core.f r6 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r6)
            java.lang.Object r2 = r5.b
            androidx.datastore.core.h r2 = (androidx.datastore.core.InterfaceC1076h) r2
            kotlinx.coroutines.flow.i r2 = r2.getData()
            r0.j = r6
            r0.m = r3
            java.lang.Object r0 = kotlinx.coroutines.flow.e0.p(r2, r0)
            if (r0 != r1) goto L4d
            return r1
        L4d:
            r4 = r0
            r0 = r6
            r6 = r4
        L50:
            androidx.datastore.preferences.core.b r6 = (androidx.datastore.preferences.core.b) r6
            java.lang.Object r6 = r6.c(r0)
            java.lang.Boolean r0 = java.lang.Boolean.TRUE
            boolean r6 = kotlin.jvm.internal.Intrinsics.b(r6, r0)
            java.lang.Boolean r6 = java.lang.Boolean.valueOf(r6)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.course.a.k(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTCallback
    public void onFailure(OTResponse otErrorResponse) {
        Intrinsics.checkNotNullParameter(otErrorResponse, "otErrorResponse");
        com.quizlet.features.consent.onetrust.d.a((com.quizlet.features.consent.onetrust.d) this.b, otErrorResponse, "FAILURE");
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTCallback
    public void onSuccess(OTResponse otSuccessResponse) {
        Intrinsics.checkNotNullParameter(otSuccessResponse, "otSuccessResponse");
        com.quizlet.features.consent.onetrust.d.a((com.quizlet.features.consent.onetrust.d) this.b, otSuccessResponse, "SUCCESS");
    }

    public a(com.quizlet.remote.model.login.magiclink.b repository) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public a(androidx.work.impl.model.e exerciseDetailsRemoteDataStore) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(exerciseDetailsRemoteDataStore, "exerciseDetailsRemoteDataStore");
        this.b = exerciseDetailsRemoteDataStore;
    }

    public a(C3 practiceTestsRepository) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(practiceTestsRepository, "practiceTestsRepository");
        this.b = practiceTestsRepository;
    }

    public a(com.google.mlkit.vision.documentscanner.internal.c termListSortRepository) {
        this.a = 14;
        Intrinsics.checkNotNullParameter(termListSortRepository, "termListSortRepository");
        this.b = termListSortRepository;
    }

    public a(com.quizlet.infra.legacysyncengine.net.c loader) {
        this.a = 28;
        Intrinsics.checkNotNullParameter(loader, "loader");
        this.b = loader;
    }

    public a(com.quizlet.remote.model.report.c repository) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public a(com.quizlet.data.repository.course.membership.c membershipRepository, androidx.work.impl.model.c dispatcher) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(membershipRepository, "membershipRepository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = membershipRepository;
    }

    public a(n eventListener) {
        this.a = 27;
        Intrinsics.checkNotNullParameter(eventListener, "eventListener");
        this.b = eventListener;
    }

    public a(Braze braze) {
        this.a = 24;
        Intrinsics.checkNotNullParameter(braze, "braze");
        this.b = braze;
    }

    public a(i folderRepository) {
        this.a = 1;
        Intrinsics.checkNotNullParameter(folderRepository, "folderRepository");
        this.b = folderRepository;
    }

    public a(com.quizlet.usecase.b questionnaireShimUseCaseMutator) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(questionnaireShimUseCaseMutator, "questionnaireShimUseCaseMutator");
        this.b = questionnaireShimUseCaseMutator;
    }

    public a(A mOkHttpClient) {
        this.a = 25;
        Intrinsics.checkNotNullParameter(mOkHttpClient, "mOkHttpClient");
        this.b = mOkHttpClient;
    }

    public a(DatabaseHelper database) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(database, "database");
        this.b = kotlin.l.b(new com.quizlet.local.ormlite.database.dao.a(database, 4));
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        io.reactivex.rxjava3.internal.operators.observable.E e = io.reactivex.rxjava3.internal.operators.observable.E.a;
        int i = 22;
        Object obj2 = null;
        int i2 = 0;
        Object obj3 = this.b;
        switch (this.a) {
            case 6:
                Throwable e2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e2, "e");
                if (!(e2 instanceof NetworkOfflineError)) {
                    return e;
                }
                ((org.slf4j.b) ((com.quizlet.data.repository.folderset.c) obj3).d).h("no network connection", e2);
                return io.reactivex.rxjava3.core.i.k(e2);
            case 7:
                Throwable e3 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e3, "e");
                ((org.slf4j.b) ((com.quizlet.data.repository.folderwithcreator.e) obj3).d).j("no network connection", e3);
                return e;
            case 8:
                User it2 = (User) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return AbstractC3770y6.a(((com.quizlet.local.ormlite.models.bookmark.a) ((com.quizlet.data.repository.explanations.myexplanations.a) ((com.quizlet.data.repository.user.e) obj3).b).b).a(kotlin.collections.A.b(it2)));
            case 10:
                Integer it3 = (Integer) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                ((com.google.firebase.crashlytics.internal.settings.b) obj3).getClass();
                ZonedDateTime zonedDateTimeAtZone = Instant.ofEpochSecond(it3.intValue()).atZone(ZoneId.systemDefault());
                Intrinsics.checkNotNullExpressionValue(zonedDateTimeAtZone, "atZone(...)");
                return Boolean.valueOf(zonedDateTimeAtZone.isAfter(ZonedDateTime.of(LocalDateTime.of(2023, com.quizlet.featuregate.features.emailconfirmation.a.a, 17, 0, 0), ZoneId.systemDefault())));
            case 12:
                return new Q(((com.quizlet.data.repository.folderset.c) ((j) obj3).b).q(), ((com.quizlet.features.infra.basestudy.data.models.dataproviders.a) obj).u.size());
            case 16:
                C4537b dataTuple = (C4537b) obj;
                Intrinsics.checkNotNullParameter(dataTuple, "dataTuple");
                G g = (G) obj3;
                if (!Intrinsics.b(g.x1, Boolean.TRUE)) {
                    return (g.P() && g.m1.isEmpty()) ? C4537b.a(dataTuple, null, K.a, 23) : dataTuple;
                }
                List list = dataTuple.a;
                ArrayList arrayList = new ArrayList();
                for (Object obj4 : list) {
                    DBTerm dBTerm = (DBTerm) obj4;
                    ArrayList arrayList2 = g.Z.n;
                    if (arrayList2 != null && arrayList2.contains(Long.valueOf(dBTerm.getId()))) {
                        arrayList.add(obj4);
                    }
                }
                return C4537b.a(dataTuple, arrayList, K.a, 22);
            case 19:
                List modelsWithIds = (List) obj;
                Intrinsics.checkNotNullParameter(modelsWithIds, "modelsWithIds");
                com.quizlet.local.ormlite.models.bookmark.a aVar = (com.quizlet.local.ormlite.models.bookmark.a) obj3;
                return new m(((com.lyft.android.scissors.b) aVar.d).f(modelsWithIds), obj2, Boolean.TRUE, i2).g(new com.quizlet.data.interactor.school.b(i, modelsWithIds, aVar));
            case EventType.WINDOW_STATE /* 22 */:
                retrofit2.K it4 = (retrofit2.K) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                return io.ktor.client.plugins.api.d.g((io.ktor.client.plugins.api.d) obj3, null, it4);
            default:
                List downloadedSets = (List) obj;
                Intrinsics.checkNotNullParameter(downloadedSets, "downloadedSets");
                if (!downloadedSets.isEmpty()) {
                    DBStudySet dBStudySet = (DBStudySet) CollectionsKt.L(downloadedSets);
                    com.quizlet.offline.managers.i iVar = (com.quizlet.offline.managers.i) obj3;
                    LinkedHashMap linkedHashMap = iVar.j;
                    Long lValueOf = Long.valueOf(dBStudySet.getId());
                    com.quizlet.features.infra.models.b offlineStatus = com.quizlet.features.infra.models.b.c;
                    linkedHashMap.put(lValueOf, offlineStatus);
                    long id = dBStudySet.getId();
                    com.quizlet.local.ormlite.models.term.b bVar = iVar.g;
                    Intrinsics.checkNotNullParameter(offlineStatus, "offlineStatus");
                    ((com.quizlet.infra.legacysyncengine.managers.i) bVar.b).c(DBOfflineEntity.create(Long.valueOf(id), G1.SET, 2));
                }
                return io.reactivex.rxjava3.internal.operators.completable.f.a;
        }
    }

    public a(InterfaceC1076h dataStore) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.b = dataStore;
    }

    public a(Function1 onSaveClick) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(onSaveClick, "onSaveClick");
        this.b = onSaveClick;
    }

    public a(EventLogger eventLogger) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.b = eventLogger;
    }
}
