package com.quizlet.features.setpage.viewmodel;

import androidx.camera.camera2.internal.C0138o;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.B6;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.authentication.SignUpWallEventLogger;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.O1;
import com.quizlet.generated.enums.y1;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.StudiableImage;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.q0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes3.dex */
public final class P extends com.quizlet.viewmodel.a implements com.quizlet.infra.legacysyncengine.datasources.b, InterfaceC4427a, com.quizlet.features.infra.folder.menu.viewmodel.n {
    public final com.quizlet.data.interactor.studiablemetadata.b A;
    public boolean A1;
    public final AbstractC5040y B;
    public long B1;
    public final com.quizlet.inapp.manager.a C;
    public boolean C1;
    public final SetPagePerformanceLogger D;
    public boolean D1;
    public final com.quizlet.remote.model.notes.e E;
    public y0 E1;
    public final com.quizlet.features.setpage.studymodes.viewmodel.a F;
    public DBStudySet F1;
    public final com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G G;
    public Object G1;
    public final com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.y H;
    public final C0138o H1;
    public final androidx.compose.foundation.text.input.internal.u I;
    public final com.quizlet.infra.legacysyncengine.datasources.w I1;
    public final SignUpWallEventLogger J;
    public final androidx.compose.ui.text.font.o J1;
    public final androidx.compose.runtime.internal.j K;
    public final s0 K1;
    public final com.quizlet.features.infra.folder.menu.viewmodel.m L;
    public final s0 L1;
    public final com.quizlet.data.repository.user.a M;
    public final s0 M1;
    public final C4203d N1;
    public final androidx.compose.ui.text.font.o O1;
    public final com.quizlet.shared.usecase.folderstudymaterials.a V;
    public final com.google.android.material.floatingactionbutton.c W;
    public final Y X;
    public final X Y;
    public final X Z;
    public final X c1;
    public final androidx.work.impl.model.c d;
    public final Y d1;
    public final EventLogger e;
    public final Y e1;
    public final com.google.firebase.messaging.p f;
    public final Y f1;
    public final SearchEventLogger g;
    public final X g1;
    public final com.quizlet.features.notes.a h;
    public final Y h1;
    public final com.features.flashcards.creatormarketing.h i;
    public final X i1;
    public final com.quizlet.infra.legacysyncengine.net.f j;
    public final X j1;
    public final UserInfoCache k;
    public final Y k1;
    public final androidx.work.impl.model.v l;
    public final Y l1;
    public final androidx.work.impl.model.n m;
    public final Y m1;
    public final androidx.work.impl.model.c n;
    public final Y n1;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e o;
    public final Y o1;
    public final com.quizlet.data.interactor.achievements.f p;
    public final X p1;
    public final com.quizlet.data.connectivity.a q;
    public final Y q1;
    public final com.quizlet.features.setpage.offline.k r;
    public long r1;
    public final com.google.firebase.heartbeatinfo.e s;
    public A1 s1;
    public final com.lyft.android.scissors.b t;
    public boolean t1;
    public final com.google.android.material.shape.e u;
    public final boolean u1;
    public final com.google.mlkit.common.internal.model.a v;
    public final AddMaterialFolderData v1;
    public final com.quizlet.features.infra.basestudy.manager.d w;
    public boolean w1;
    public final com.quizlet.infra.legacysyncengine.features.properties.d x;
    public io.reactivex.rxjava3.subjects.h x1;
    public final com.google.mlkit.vision.documentscanner.internal.c y;
    public final io.reactivex.rxjava3.subjects.d y1;
    public final com.google.android.gms.measurement.internal.J z;
    public final io.reactivex.rxjava3.subjects.d z1;

    public P(m0 savedStateHandle, com.google.android.gms.measurement.internal.J setPageDataProviderFactory, com.quizlet.infra.legacysyncengine.datasources.factory.b termAndSelectedTermDataSourceFactory, androidx.work.impl.model.c userProperties, EventLogger eventLogger, com.google.firebase.messaging.p setPageLogger, SearchEventLogger searchEventLogger, com.quizlet.features.notes.a classContentLogger, com.quizlet.quizletandroid.ui.folder.logging.a folderSetsLogger, com.features.flashcards.creatormarketing.h progressLogger, com.quizlet.infra.legacysyncengine.net.f syncDispatcher, UserInfoCache userInfoCache, androidx.work.impl.model.v setInSelectedTermsModeUseCase, androidx.work.impl.model.n permissionsChecker, androidx.work.impl.model.c setPageShortcutManager, com.quizlet.data.repository.folderwithcreatorinclass.e copySetApi, com.quizlet.data.interactor.achievements.f addToClassPermissionHelper, com.quizlet.data.connectivity.a networkConnectivityManager, com.quizlet.features.setpage.offline.k setPageOfflineManager, com.google.firebase.heartbeatinfo.e shareSetFeature, com.lyft.android.scissors.b shareSetOnWhatsAppFeature, com.google.android.material.shape.e shareSetByEmailFeature, com.google.mlkit.common.internal.model.a setPageProgressFeature, com.quizlet.features.infra.basestudy.manager.d studyFunnelEventManager, com.quizlet.infra.legacysyncengine.features.properties.d _studySetProperties, com.google.mlkit.vision.documentscanner.internal.c setPageAdFeature, com.google.android.gms.measurement.internal.J expertSolutionsUpsellManager, com.quizlet.data.interactor.studiablemetadata.b studiableMetadataUseCase, AbstractC5040y ioDispatcher, com.quizlet.inapp.manager.a reviewManager, SetPagePerformanceLogger setPagePerformanceLogger, com.quizlet.remote.model.notes.e syncStudyModeModelsUseCase, com.quizlet.features.setpage.studymodes.viewmodel.a startStudyModeManager, com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G setPageStudyModesManager, com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.y setPageStudyModeMeteringManager, androidx.compose.foundation.text.input.internal.u achievementsEventUseCase, SignUpWallEventLogger signUpWallEventLogger, androidx.compose.runtime.internal.j getSetPageMenuItemsUseCase, com.quizlet.features.infra.folder.menu.viewmodel.m addToFolderMenuViewModelDelegate, com.quizlet.data.repository.user.a termListComposeFeature, FolderLogger folderEventLogger, com.quizlet.shared.usecase.folderstudymaterials.a gamesSetEligibilityChecker, com.google.android.material.floatingactionbutton.c setPageOverflowMenuFactory) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(setPageDataProviderFactory, "setPageDataProviderFactory");
        Intrinsics.checkNotNullParameter(termAndSelectedTermDataSourceFactory, "termAndSelectedTermDataSourceFactory");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(setPageLogger, "setPageLogger");
        Intrinsics.checkNotNullParameter(searchEventLogger, "searchEventLogger");
        Intrinsics.checkNotNullParameter(classContentLogger, "classContentLogger");
        Intrinsics.checkNotNullParameter(folderSetsLogger, "folderSetsLogger");
        Intrinsics.checkNotNullParameter(progressLogger, "progressLogger");
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(setInSelectedTermsModeUseCase, "setInSelectedTermsModeUseCase");
        Intrinsics.checkNotNullParameter(permissionsChecker, "permissionsChecker");
        Intrinsics.checkNotNullParameter(setPageShortcutManager, "setPageShortcutManager");
        Intrinsics.checkNotNullParameter(copySetApi, "copySetApi");
        Intrinsics.checkNotNullParameter(addToClassPermissionHelper, "addToClassPermissionHelper");
        Intrinsics.checkNotNullParameter(networkConnectivityManager, "networkConnectivityManager");
        Intrinsics.checkNotNullParameter(setPageOfflineManager, "setPageOfflineManager");
        Intrinsics.checkNotNullParameter(shareSetFeature, "shareSetFeature");
        Intrinsics.checkNotNullParameter(shareSetOnWhatsAppFeature, "shareSetOnWhatsAppFeature");
        Intrinsics.checkNotNullParameter(shareSetByEmailFeature, "shareSetByEmailFeature");
        Intrinsics.checkNotNullParameter(setPageProgressFeature, "setPageProgressFeature");
        Intrinsics.checkNotNullParameter(studyFunnelEventManager, "studyFunnelEventManager");
        Intrinsics.checkNotNullParameter(_studySetProperties, "_studySetProperties");
        Intrinsics.checkNotNullParameter(setPageAdFeature, "setPageAdFeature");
        Intrinsics.checkNotNullParameter(expertSolutionsUpsellManager, "expertSolutionsUpsellManager");
        Intrinsics.checkNotNullParameter(studiableMetadataUseCase, "studiableMetadataUseCase");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        Intrinsics.checkNotNullParameter(reviewManager, "reviewManager");
        Intrinsics.checkNotNullParameter(setPagePerformanceLogger, "setPagePerformanceLogger");
        Intrinsics.checkNotNullParameter(syncStudyModeModelsUseCase, "syncStudyModeModelsUseCase");
        Intrinsics.checkNotNullParameter(startStudyModeManager, "startStudyModeManager");
        Intrinsics.checkNotNullParameter(setPageStudyModesManager, "setPageStudyModesManager");
        Intrinsics.checkNotNullParameter(setPageStudyModeMeteringManager, "setPageStudyModeMeteringManager");
        Intrinsics.checkNotNullParameter(achievementsEventUseCase, "achievementsEventUseCase");
        Intrinsics.checkNotNullParameter(signUpWallEventLogger, "signUpWallEventLogger");
        Intrinsics.checkNotNullParameter(getSetPageMenuItemsUseCase, "getSetPageMenuItemsUseCase");
        Intrinsics.checkNotNullParameter(addToFolderMenuViewModelDelegate, "addToFolderMenuViewModelDelegate");
        Intrinsics.checkNotNullParameter(termListComposeFeature, "termListComposeFeature");
        Intrinsics.checkNotNullParameter(folderEventLogger, "folderEventLogger");
        Intrinsics.checkNotNullParameter(gamesSetEligibilityChecker, "gamesSetEligibilityChecker");
        Intrinsics.checkNotNullParameter(setPageOverflowMenuFactory, "setPageOverflowMenuFactory");
        this.d = userProperties;
        this.e = eventLogger;
        this.f = setPageLogger;
        this.g = searchEventLogger;
        this.h = classContentLogger;
        this.i = progressLogger;
        this.j = syncDispatcher;
        this.k = userInfoCache;
        this.l = setInSelectedTermsModeUseCase;
        this.m = permissionsChecker;
        this.n = setPageShortcutManager;
        this.o = copySetApi;
        this.p = addToClassPermissionHelper;
        this.q = networkConnectivityManager;
        this.r = setPageOfflineManager;
        this.s = shareSetFeature;
        this.t = shareSetOnWhatsAppFeature;
        this.u = shareSetByEmailFeature;
        this.v = setPageProgressFeature;
        this.w = studyFunnelEventManager;
        this.x = _studySetProperties;
        this.y = setPageAdFeature;
        this.z = expertSolutionsUpsellManager;
        this.A = studiableMetadataUseCase;
        this.B = ioDispatcher;
        this.C = reviewManager;
        this.D = setPagePerformanceLogger;
        this.E = syncStudyModeModelsUseCase;
        this.F = startStudyModeManager;
        this.G = setPageStudyModesManager;
        this.H = setPageStudyModeMeteringManager;
        this.I = achievementsEventUseCase;
        this.J = signUpWallEventLogger;
        this.K = getSetPageMenuItemsUseCase;
        this.L = addToFolderMenuViewModelDelegate;
        this.M = termListComposeFeature;
        this.V = gamesSetEligibilityChecker;
        this.W = setPageOverflowMenuFactory;
        this.X = new Y();
        this.Y = new X(1);
        this.Z = new X(1);
        this.c1 = new X(1);
        this.d1 = new Y();
        this.e1 = new Y();
        this.f1 = new Y();
        this.g1 = new X(1);
        this.h1 = new Y();
        this.i1 = new X(1);
        this.j1 = new X(1);
        this.k1 = new Y();
        this.l1 = new Y();
        this.m1 = new Y();
        this.n1 = new Y();
        this.o1 = new Y();
        this.p1 = new X(1);
        this.q1 = new Y();
        Long l = (Long) savedStateHandle.a("setId");
        this.r1 = l != null ? l.longValue() : 0L;
        this.s1 = (A1) savedStateHandle.a("studyMode");
        Boolean bool = (Boolean) savedStateHandle.a("isNewStudySet");
        this.t1 = bool != null ? bool.booleanValue() : false;
        Boolean bool2 = (Boolean) savedStateHandle.a("isFromHome");
        this.u1 = bool2 != null ? bool2.booleanValue() : false;
        this.v1 = (AddMaterialFolderData) savedStateHandle.a("addMaterialFolderData");
        Boolean bool3 = (Boolean) savedStateHandle.a("shouldGoToEditSet");
        this.w1 = bool3 != null ? bool3.booleanValue() : false;
        io.reactivex.rxjava3.subjects.h hVar = new io.reactivex.rxjava3.subjects.h();
        Intrinsics.checkNotNullExpressionValue(hVar, "create(...)");
        this.x1 = hVar;
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
        this.y1 = dVarZ;
        io.reactivex.rxjava3.subjects.d dVarZ2 = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ2, "create(...)");
        this.z1 = dVarZ2;
        kotlin.collections.K k = kotlin.collections.K.a;
        this.G1 = k;
        this.H1 = new C0138o((com.quizlet.infra.legacysyncengine.net.c) setPageDataProviderFactory.c, D(), setPageDataProviderFactory.b, (io.ktor.client.plugins.api.d) setPageDataProviderFactory.d, (com.quizlet.shared.usecase.srs.a) setPageDataProviderFactory.e);
        this.I1 = termAndSelectedTermDataSourceFactory.a(D());
        C5041z c5041z = C5041z.a;
        androidx.compose.ui.text.font.o oVar = new androidx.compose.ui.text.font.o(c5041z, 7);
        this.J1 = oVar;
        this.K1 = e0.c(k);
        this.L1 = e0.c(new com.quizlet.features.setpage.screenstates.F(String.valueOf(D()), false, false));
        this.M1 = e0.c(com.quizlet.features.setpage.screenstates.s.a);
        setPagePerformanceLogger.j();
        kotlinx.coroutines.E.A(p0.j(this), oVar, null, new G(this, null), 2);
        K();
        kotlinx.coroutines.E.A(p0.j(this), null, null, new q(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new v(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new w(this, null), 3);
        folderEventLogger.setScreenName("set_page");
        this.N1 = new C4203d(this);
        this.O1 = new androidx.compose.ui.text.font.o(c5041z, 8);
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x008c, code lost:
    
        if (r5 == r1) goto L31;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object B(com.quizlet.features.setpage.viewmodel.P r5, com.quizlet.features.infra.basestudy.data.models.MeteredValue r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5.getClass()
            boolean r0 = r7 instanceof com.quizlet.features.setpage.viewmodel.C4432f
            if (r0 == 0) goto L16
            r0 = r7
            com.quizlet.features.setpage.viewmodel.f r0 = (com.quizlet.features.setpage.viewmodel.C4432f) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            com.quizlet.features.setpage.viewmodel.f r0 = new com.quizlet.features.setpage.viewmodel.f
            r0.<init>(r5, r7)
        L1b:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3d
            if (r2 == r4) goto L35
            if (r2 != r3) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L8f
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            com.quizlet.features.infra.basestudy.data.models.MeteredValue r6 = r0.k
            com.quizlet.features.setpage.viewmodel.P r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L57
        L3d:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            androidx.work.impl.model.c r7 = r5.d
            io.reactivex.rxjava3.internal.operators.single.g r7 = r7.q()
            io.reactivex.rxjava3.internal.operators.single.g r7 = com.google.android.gms.dynamite.d.e(r7)
            r0.j = r5
            r0.k = r6
            r0.n = r4
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r7, r0)
            if (r7 != r1) goto L57
            goto L8e
        L57:
            java.lang.String r2 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r2)
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 != 0) goto L6e
            boolean r6 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3241q5.d(r6)
            if (r6 == 0) goto L6b
            goto L6e
        L6b:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L6e:
            r6 = 0
            r0.j = r6
            r0.k = r6
            r0.n = r3
            com.quizlet.data.interactor.studiablemetadata.b r7 = r5.A
            long r2 = r5.D()
            r7.getClass()
            com.quizlet.data.interactor.studiablemetadata.a r5 = new com.quizlet.data.interactor.studiablemetadata.a
            r5.<init>(r7, r2, r6)
            java.lang.Object r5 = kotlinx.coroutines.E.m(r5, r0)
            if (r5 != r1) goto L8a
            goto L8c
        L8a:
            kotlin.Unit r5 = kotlin.Unit.a
        L8c:
            if (r5 != r1) goto L8f
        L8e:
            return r1
        L8f:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.viewmodel.P.B(com.quizlet.features.setpage.viewmodel.P, com.quizlet.features.infra.basestudy.data.models.MeteredValue, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void C(com.quizlet.qutils.string.f fVar) {
        this.p1.j(new com.quizlet.features.infra.snackbar.l(com.quizlet.features.infra.snackbar.k.c, -1, fVar, null, null, 120));
    }

    public final long D() {
        if (G()) {
            DBStudySet dBStudySet = this.F1;
            if (dBStudySet != null) {
                return dBStudySet.getSetId();
            }
            Intrinsics.m("set");
            throw null;
        }
        long j = this.r1;
        if (j != 0) {
            return j;
        }
        timber.log.c.a.e(new RuntimeException("No set id provided"));
        return 0L;
    }

    public final io.reactivex.rxjava3.internal.operators.flowable.b E() {
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.activitycenter.a(this, 1), 4);
        Intrinsics.checkNotNullExpressionValue(bVar, "defer(...)");
        return bVar;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, java.util.List] */
    public final boolean F() {
        DBStudySet dBStudySet = this.F1;
        if (dBStudySet == null) {
            Intrinsics.m("set");
            throw null;
        }
        boolean hasDiagrams = dBStudySet.getHasDiagrams();
        ?? r1 = this.G1;
        this.V.getClass();
        return com.quizlet.shared.usecase.folderstudymaterials.a.p(r1, hasDiagrams);
    }

    public final boolean G() {
        return this.F1 != null;
    }

    public final void H(Function1 function1) {
        kotlinx.coroutines.E.A(p0.j(this), this.N1, null, new C4438l(this, function1, null), 2);
    }

    public final void I(Function0 function0, Function1 function1) {
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4441o(this, function0, function1, null), 3);
    }

    public final void J(A1 a1) {
        int i = AbstractC4431e.a[a1.ordinal()];
        if (i == 1) {
            N(true);
        } else {
            if (i == 2) {
                M(true);
                return;
            }
            throw new IllegalArgumentException("Invalid study type " + a1 + " is not a game");
        }
    }

    public final void K() {
        C0138o c0138o = this.H1;
        c0138o.getClass();
        io.reactivex.rxjava3.internal.operators.observable.J jQ = ((io.reactivex.rxjava3.subjects.d) c0138o.h).q(new com.google.firebase.crashlytics.internal.settings.b(c0138o, 21));
        Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
        io.reactivex.rxjava3.internal.observers.h hVarD = B7.d(jQ, new com.quizlet.features.practicetest.navigation.a(21), null, new C4429c(this, 1), 2);
        Intrinsics.checkNotNullParameter(hVarD, "<this>");
        A(hVarD);
        kotlinx.coroutines.E.A(p0.j(this), new androidx.compose.ui.text.font.o(C5041z.a, 6), null, new C4442p(this, null), 2);
    }

    public final void L() {
        com.quizlet.features.infra.models.studymodeshared.b bVar;
        A1 a1 = this.s1;
        if (a1 != null) {
            Intrinsics.checkNotNullParameter(a1, "<this>");
            switch (com.quizlet.features.infra.models.studymodeshared.c.a[a1.ordinal()]) {
                case 1:
                    bVar = com.quizlet.features.infra.models.studymodeshared.b.b;
                    break;
                case 2:
                    bVar = com.quizlet.features.infra.models.studymodeshared.b.c;
                    break;
                case 3:
                    bVar = com.quizlet.features.infra.models.studymodeshared.b.a;
                    break;
                case 4:
                    bVar = com.quizlet.features.infra.models.studymodeshared.b.d;
                    break;
                case 5:
                    bVar = com.quizlet.features.infra.models.studymodeshared.b.e;
                    break;
                case 6:
                    bVar = com.quizlet.features.infra.models.studymodeshared.b.f;
                    break;
                default:
                    bVar = null;
                    break;
            }
            if (bVar == null) {
                return;
            }
            int iOrdinal = bVar.ordinal();
            if (iOrdinal == 0) {
                I(new C4428b(this, 0), new D(this, null, null));
            } else if (iOrdinal == 1) {
                H(new C(this, null));
            } else if (iOrdinal == 2) {
                H(new E(this, null));
            } else if (iOrdinal == 3) {
                I(new C4428b(this, 3), new F(this, null));
            } else if (iOrdinal == 4) {
                J(A1.BLOCKS);
            } else {
                if (iOrdinal != 5) {
                    throw new NoWhenBranchMatchedException();
                }
                J(A1.SINGLE_PLAYER_BLAST);
            }
            this.s1 = null;
            this.l1.j(com.quizlet.features.setpage.screenstates.i.a);
        }
    }

    public final void M(boolean z) {
        if (z) {
            I(new C4428b(this, 1), new A(this, null));
            return;
        }
        com.quizlet.features.infra.snackbar.d dVar = com.quizlet.features.infra.snackbar.k.b;
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        this.p1.j(new com.quizlet.features.infra.snackbar.l(dVar, -1, new com.quizlet.qutils.string.f(R.string.games_not_available, C4933y.P(args)), null, null, 120));
    }

    public final void N(boolean z) {
        if (z) {
            I(new C4428b(this, 2), new B(this, null));
            return;
        }
        com.quizlet.features.infra.snackbar.d dVar = com.quizlet.features.infra.snackbar.k.b;
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        this.p1.j(new com.quizlet.features.infra.snackbar.l(dVar, -1, new com.quizlet.qutils.string.f(R.string.games_not_available, C4933y.P(args)), null, null, 120));
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final q0 b() {
        return this.L.k;
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void c(com.quizlet.features.infra.folder.menu.data.b option, boolean z) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.L.c(option, z);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void e(com.quizlet.data.interactor.folderstudymaterial.g undoAction) {
        Intrinsics.checkNotNullParameter(undoAction, "undoAction");
        this.L.e(undoAction);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void f(long j, List tags) {
        Intrinsics.checkNotNullParameter(tags, "tags");
        this.L.f(j, tags);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final InterfaceC4992i g() {
        return this.L.i;
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.b
    public final void h(List data) {
        StudiableImage studiableImage;
        Intrinsics.checkNotNullParameter(data, "data");
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(data, 10));
        Iterator it2 = data.iterator();
        while (it2.hasNext()) {
            arrayList.add((DBTerm) ((Pair) it2.next()).a);
        }
        this.G1 = arrayList;
        this.z1.b(arrayList);
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            DBTerm dBTerm = (DBTerm) it3.next();
            long id = dBTerm.getId();
            long localId = dBTerm.getLocalId();
            com.quizlet.features.infra.models.a aVarE = B6.e(dBTerm, O1.WORD);
            com.quizlet.features.infra.models.a aVarE2 = B6.e(dBTerm, O1.DEFINITION);
            DBImage definitionImage = dBTerm.getDefinitionImage();
            if (definitionImage != null) {
                Intrinsics.checkNotNullParameter(definitionImage, "<this>");
                String smallUrl = definitionImage.getSmallUrl();
                String mediumUrl = definitionImage.getMediumUrl();
                String largeUrl = definitionImage.getLargeUrl();
                Integer width = definitionImage.getWidth();
                int iIntValue = width != null ? width.intValue() : 0;
                Integer height = definitionImage.getHeight();
                studiableImage = new StudiableImage(smallUrl, iIntValue, mediumUrl, largeUrl, height != null ? height.intValue() : 0);
            } else {
                studiableImage = null;
            }
            arrayList2.add(new com.quizlet.features.setpage.studypreview.data.a(id, localId, aVarE, aVarE2, studiableImage));
        }
        io.reactivex.rxjava3.subjects.h hVar = this.x1;
        com.quizlet.billing.manager.b bVar = new com.quizlet.billing.manager.b(this, arrayList2, 6);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
        io.reactivex.rxjava3.internal.functions.b bVar2 = io.reactivex.rxjava3.internal.functions.d.c;
        hVar.getClass();
        io.reactivex.rxjava3.internal.operators.completable.l lVar = new io.reactivex.rxjava3.internal.operators.completable.l(bVar, gVar, bVar2);
        hVar.e(lVar);
        Intrinsics.checkNotNullExpressionValue(lVar, "subscribe(...)");
        Intrinsics.checkNotNullParameter(lVar, "<this>");
        A(lVar);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final q0 i() {
        return this.L.g;
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final InterfaceC4992i j() {
        return this.L.j;
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void k(String studyMaterialId, y1 studyMaterialType, AddMaterialFolderData data) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        Intrinsics.checkNotNullParameter(data, "data");
        this.L.k(studyMaterialId, studyMaterialType, data);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void l(long j, long j2, String folderTitle) {
        Intrinsics.checkNotNullParameter(folderTitle, "folderTitle");
        this.L.l(j, j2, folderTitle);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void n() {
        this.L.n();
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void o(String studyMaterialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.L.o(studyMaterialId, studyMaterialType);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void p() {
        this.L.p();
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void q(com.quizlet.features.infra.folder.menu.data.g option) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.L.q(option);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void r(com.quizlet.features.infra.folder.menu.data.g option) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.L.r(option);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void s() {
        this.L.s();
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final InterfaceC4992i u() {
        return this.L.u();
    }

    /* JADX WARN: Type inference failed for: r1v3, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // com.quizlet.viewmodel.a, com.quizlet.viewmodel.b, androidx.lifecycle.w0
    public final void z() {
        super.z();
        C0138o c0138o = this.H1;
        ((io.reactivex.rxjava3.subjects.r) c0138o.i).onSuccess(Unit.a);
        ((AtomicReference) c0138o.g).dispose();
        c0138o.g = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        ((com.quizlet.features.infra.studysetting.datasource.a) c0138o.d).g();
        ((com.quizlet.features.infra.studysetting.datasource.a) c0138o.e).g();
        ((com.quizlet.features.infra.studysetting.datasource.a) c0138o.f).g();
        this.g.k();
        this.D.a();
        ((com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s) this.F).l.onSuccess(Unit.a);
        this.L.v();
    }
}
