package com.quizlet.quizletandroid.ui.startpage.nav2;

import android.content.SharedPreferences;
import androidx.lifecycle.p0;
import androidx.paging.J0;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_barcode.C6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3603d6;
import com.quizlet.data.model.v2;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.home.HomeEdgyEventLogger;
import com.quizlet.eventlogger.features.revisioncenter.RevisionCenterLogger;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.AbstractC4707c;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4721q;
import io.reactivex.rxjava3.internal.operators.observable.C4905y;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.h0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class Y extends com.quizlet.viewmodel.a implements com.quizlet.features.home.viewmodel.e {
    public final com.quizlet.quizletandroid.ui.globalnav.logging.a A;
    public final UserInfoCache B;
    public final androidx.lifecycle.Y C;
    public final androidx.lifecycle.Y D;
    public final androidx.lifecycle.Y E;
    public final androidx.lifecycle.Y F;
    public final androidx.lifecycle.Y G;
    public final androidx.lifecycle.Y H;
    public final androidx.lifecycle.Y I;
    public final androidx.lifecycle.Y J;
    public final androidx.lifecycle.Y K;
    public final androidx.lifecycle.Y L;
    public final androidx.lifecycle.Y M;
    public final androidx.lifecycle.Y V;
    public final androidx.lifecycle.Y W;
    public final androidx.lifecycle.Y X;
    public final androidx.lifecycle.X Y;
    public final s0 Z;
    public final com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p c1;
    public final io.reactivex.rxjava3.core.o d;
    public final androidx.lifecycle.Y d1;
    public final io.reactivex.rxjava3.core.o e;
    public final androidx.lifecycle.Y e1;
    public final androidx.work.impl.model.c f;
    public final androidx.lifecycle.Y f1;
    public final com.quizlet.infra.legacysyncengine.managers.d g;
    public final androidx.lifecycle.Y g1;
    public final EventLogger h;
    public final androidx.lifecycle.Y h1;
    public final SharedPreferences i;
    public final androidx.lifecycle.Y i1;
    public final com.quizlet.features.infra.basestudy.manager.d j;
    public final androidx.lifecycle.Y j1;
    public final com.quizlet.quizletandroid.braze.events.b k;
    public final androidx.lifecycle.Y k1;
    public final androidx.work.impl.model.e l;
    public final androidx.lifecycle.Y l1;
    public final com.quizlet.data.repository.login.a m;
    public final androidx.lifecycle.Y m1;
    public final com.quizlet.offline.managers.b n;
    public final androidx.lifecycle.Y n1;
    public final androidx.compose.foundation.text.input.internal.u o;
    public final androidx.lifecycle.Y o1;
    public final com.quizlet.featuregate.features.home.a p;
    public final androidx.lifecycle.Y p1;
    public final com.lyft.android.scissors.b q;
    public final androidx.lifecycle.Y q1;
    public final com.lyft.android.scissors.b r;
    public final androidx.lifecycle.X r1;
    public final com.google.mlkit.common.sdkinternal.model.a s;
    public final androidx.lifecycle.X s1;
    public final C4721q t;
    public final androidx.lifecycle.X t1;
    public final HomeEdgyEventLogger u;
    public final kotlin.u u1;
    public final com.quizlet.quizletandroid.ui.startpage.nav2.logging.a v;
    public final io.reactivex.rxjava3.subjects.d v1;
    public final com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k w;
    public com.quizlet.quizletandroid.ui.startpage.nav2.model.K w1;
    public final RevisionCenterLogger x;
    public final io.reactivex.rxjava3.disposables.a x1;
    public final com.google.firebase.crashlytics.internal.settings.b y;
    public final s0 y1;
    public final com.quizlet.shared.usecase.folderstudymaterials.b z;
    public final kotlinx.coroutines.flow.Z z1;

    public Y(io.reactivex.rxjava3.core.o requestScheduler, io.reactivex.rxjava3.core.o mainThreadScheduler, androidx.work.impl.model.c userProperties, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, EventLogger eventLogger, SharedPreferences sharedPreferences, com.quizlet.features.infra.basestudy.manager.d studyFunnelEventManager, com.quizlet.quizletandroid.braze.events.b brazeViewScreenEventManager, androidx.work.impl.model.e homeDataSectionProvider, com.quizlet.data.repository.login.a emptyHomeAddCoursesFeature, com.quizlet.offline.managers.b offlineStateManager, androidx.compose.foundation.text.input.internal.u markStudySetAsIrrelevantRecommendationUseCase, com.quizlet.featuregate.features.home.a activityCenterFeature, com.lyft.android.scissors.b getActivityCenterUnreadCountUseCase, com.lyft.android.scissors.b syncEverythingUseCase, com.google.mlkit.common.sdkinternal.model.a achievementsStreakDataProvider, C4721q homeCacheData, HomeEdgyEventLogger homeEdgyEventLogger, com.quizlet.quizletandroid.ui.startpage.nav2.logging.a homeEventLogger, com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k revisionCenterPresentationUseCase, RevisionCenterLogger revisionCenterLogger, com.google.firebase.crashlytics.internal.settings.b checkNotesEligibilityUseCase, com.quizlet.shared.usecase.folderstudymaterials.b ageLocationRecommendationsFeature, com.quizlet.quizletandroid.ui.globalnav.logging.a newGlobalNavigationEventLogger, UserInfoCache userInfoCache) {
        Intrinsics.checkNotNullParameter(requestScheduler, "requestScheduler");
        Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        Intrinsics.checkNotNullParameter(studyFunnelEventManager, "studyFunnelEventManager");
        Intrinsics.checkNotNullParameter(brazeViewScreenEventManager, "brazeViewScreenEventManager");
        Intrinsics.checkNotNullParameter(homeDataSectionProvider, "homeDataSectionProvider");
        Intrinsics.checkNotNullParameter(emptyHomeAddCoursesFeature, "emptyHomeAddCoursesFeature");
        Intrinsics.checkNotNullParameter(offlineStateManager, "offlineStateManager");
        Intrinsics.checkNotNullParameter(markStudySetAsIrrelevantRecommendationUseCase, "markStudySetAsIrrelevantRecommendationUseCase");
        Intrinsics.checkNotNullParameter(activityCenterFeature, "activityCenterFeature");
        Intrinsics.checkNotNullParameter(getActivityCenterUnreadCountUseCase, "getActivityCenterUnreadCountUseCase");
        Intrinsics.checkNotNullParameter(syncEverythingUseCase, "syncEverythingUseCase");
        Intrinsics.checkNotNullParameter(achievementsStreakDataProvider, "achievementsStreakDataProvider");
        Intrinsics.checkNotNullParameter(homeCacheData, "homeCacheData");
        Intrinsics.checkNotNullParameter(homeEdgyEventLogger, "homeEdgyEventLogger");
        Intrinsics.checkNotNullParameter(homeEventLogger, "homeEventLogger");
        Intrinsics.checkNotNullParameter(revisionCenterPresentationUseCase, "revisionCenterPresentationUseCase");
        Intrinsics.checkNotNullParameter(revisionCenterLogger, "revisionCenterLogger");
        Intrinsics.checkNotNullParameter(checkNotesEligibilityUseCase, "checkNotesEligibilityUseCase");
        Intrinsics.checkNotNullParameter(ageLocationRecommendationsFeature, "ageLocationRecommendationsFeature");
        Intrinsics.checkNotNullParameter(newGlobalNavigationEventLogger, "newGlobalNavigationEventLogger");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        this.d = requestScheduler;
        this.e = mainThreadScheduler;
        this.f = userProperties;
        this.g = loggedInUserManager;
        this.h = eventLogger;
        this.i = sharedPreferences;
        this.j = studyFunnelEventManager;
        this.k = brazeViewScreenEventManager;
        this.l = homeDataSectionProvider;
        this.m = emptyHomeAddCoursesFeature;
        this.n = offlineStateManager;
        this.o = markStudySetAsIrrelevantRecommendationUseCase;
        this.p = activityCenterFeature;
        this.q = getActivityCenterUnreadCountUseCase;
        this.r = syncEverythingUseCase;
        this.s = achievementsStreakDataProvider;
        this.t = homeCacheData;
        this.u = homeEdgyEventLogger;
        this.v = homeEventLogger;
        this.w = revisionCenterPresentationUseCase;
        this.x = revisionCenterLogger;
        this.y = checkNotesEligibilityUseCase;
        this.z = ageLocationRecommendationsFeature;
        this.A = newGlobalNavigationEventLogger;
        this.B = userInfoCache;
        androidx.lifecycle.Y y = new androidx.lifecycle.Y();
        this.C = y;
        androidx.lifecycle.Y y2 = new androidx.lifecycle.Y();
        this.D = y2;
        androidx.lifecycle.Y y3 = new androidx.lifecycle.Y();
        this.E = y3;
        androidx.lifecycle.Y y4 = new androidx.lifecycle.Y();
        this.F = y4;
        androidx.lifecycle.Y y5 = new androidx.lifecycle.Y();
        this.G = y5;
        androidx.lifecycle.Y y6 = new androidx.lifecycle.Y();
        this.H = y6;
        androidx.lifecycle.Y y7 = new androidx.lifecycle.Y();
        this.I = y7;
        androidx.lifecycle.Y y8 = new androidx.lifecycle.Y();
        this.J = y8;
        androidx.lifecycle.Y y9 = new androidx.lifecycle.Y();
        this.K = y9;
        androidx.lifecycle.Y y10 = new androidx.lifecycle.Y();
        this.L = y10;
        androidx.lifecycle.Y y11 = new androidx.lifecycle.Y();
        this.M = y11;
        androidx.lifecycle.Y y12 = new androidx.lifecycle.Y();
        this.V = y12;
        androidx.lifecycle.Y y13 = new androidx.lifecycle.Y();
        this.W = y13;
        androidx.lifecycle.Y y14 = new androidx.lifecycle.Y();
        this.X = y14;
        this.Y = C6.a(kotlin.collections.B.j(y, y2, y3, y7, y8, y4, y5, y6, y9, y10, y11, y12, y13, y14), new C4730u(this, 1));
        this.Z = e0.c(com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.q.a);
        com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o explanationsState = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(false, false);
        com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o studySetsState = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(false, false);
        com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o foldersState = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(false, false);
        com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o classesState = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(false, false);
        com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o behaviorRecsState = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(false, false);
        com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o schoolCourseRecsState = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(false, false);
        com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o ageLocationRecsState = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(false, false);
        com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o magicNotesState = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(false, false);
        Intrinsics.checkNotNullParameter(explanationsState, "explanationsState");
        Intrinsics.checkNotNullParameter(studySetsState, "studySetsState");
        Intrinsics.checkNotNullParameter(foldersState, "foldersState");
        Intrinsics.checkNotNullParameter(classesState, "classesState");
        Intrinsics.checkNotNullParameter(behaviorRecsState, "behaviorRecsState");
        Intrinsics.checkNotNullParameter(schoolCourseRecsState, "schoolCourseRecsState");
        Intrinsics.checkNotNullParameter(ageLocationRecsState, "ageLocationRecsState");
        Intrinsics.checkNotNullParameter(magicNotesState, "magicNotesState");
        com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p pVar = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p();
        pVar.a = explanationsState;
        pVar.b = studySetsState;
        pVar.c = foldersState;
        pVar.d = classesState;
        pVar.e = behaviorRecsState;
        pVar.f = schoolCourseRecsState;
        pVar.g = ageLocationRecsState;
        pVar.h = magicNotesState;
        this.c1 = pVar;
        this.d1 = new androidx.lifecycle.Y();
        this.e1 = new androidx.lifecycle.Y();
        this.f1 = new androidx.lifecycle.Y();
        this.g1 = new androidx.lifecycle.Y();
        this.h1 = new androidx.lifecycle.Y();
        this.i1 = new androidx.lifecycle.Y();
        this.j1 = new androidx.lifecycle.Y();
        this.k1 = new androidx.lifecycle.Y();
        this.l1 = new androidx.lifecycle.Y();
        this.m1 = new androidx.lifecycle.Y();
        this.n1 = new androidx.lifecycle.Y();
        this.o1 = new androidx.lifecycle.Y();
        this.p1 = new androidx.lifecycle.Y();
        this.q1 = new androidx.lifecycle.Y();
        this.r1 = new androidx.lifecycle.X(1);
        this.s1 = new androidx.lifecycle.X(1);
        this.t1 = new androidx.lifecycle.X(1);
        this.u1 = kotlin.l.b(new com.quizlet.login.resetpassword.ui.a(25));
        kotlin.collections.K k = kotlin.collections.K.a;
        Objects.requireNonNull(k, "defaultValue is null");
        io.reactivex.rxjava3.subjects.d dVar = new io.reactivex.rxjava3.subjects.d(k);
        Intrinsics.checkNotNullExpressionValue(dVar, "createDefault(...)");
        this.v1 = dVar;
        this.x1 = new io.reactivex.rxjava3.disposables.a();
        J(false);
        v2 v2Var = v2.d;
        s0 s0VarC = e0.c(v2Var);
        this.y1 = s0VarC;
        this.z1 = e0.x(new J0(new C4753y(this, null), s0VarC), p0.j(this), h0.a(3), v2Var);
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x0061, code lost:
    
        if (r7 == r1) goto L23;
     */
    /* JADX WARN: Removed duplicated region for block: B:29:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object B(com.quizlet.quizletandroid.ui.startpage.nav2.Y r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r6.getClass()
            boolean r0 = r7 instanceof com.quizlet.quizletandroid.ui.startpage.nav2.U
            if (r0 == 0) goto L16
            r0 = r7
            com.quizlet.quizletandroid.ui.startpage.nav2.U r0 = (com.quizlet.quizletandroid.ui.startpage.nav2.U) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.quizletandroid.ui.startpage.nav2.U r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.U
            r0.<init>(r6, r7)
        L1b:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3d
            if (r2 == r4) goto L37
            if (r2 != r3) goto L2f
            com.quizlet.quizletandroid.ui.startpage.nav2.Y r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L64
        L2f:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L37:
            com.quizlet.quizletandroid.ui.startpage.nav2.Y r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4f
        L3d:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r6
            r0.m = r4
            com.quizlet.featuregate.features.home.a r7 = r6.p
            androidx.work.impl.model.c r2 = r6.f
            java.lang.Object r7 = r7.a(r2, r0)
            if (r7 != r1) goto L4f
            goto L63
        L4f:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 == 0) goto L6b
            com.lyft.android.scissors.b r7 = r6.q
            r0.j = r6
            r0.m = r3
            java.lang.Object r7 = r7.a(r0)
            if (r7 != r1) goto L64
        L63:
            return r1
        L64:
            java.lang.Number r7 = (java.lang.Number) r7
            int r7 = r7.intValue()
            goto L6c
        L6b:
            r7 = 0
        L6c:
            kotlinx.coroutines.flow.s0 r0 = r6.y1
        L6e:
            java.lang.Object r1 = r0.getValue()
            r2 = r1
            com.quizlet.data.model.v2 r2 = (com.quizlet.data.model.v2) r2
            com.quizlet.db.data.caches.UserInfoCache r3 = r6.B
            java.lang.String r4 = r3.getUsername()
            java.lang.String r5 = ""
            if (r4 != 0) goto L80
            r4 = r5
        L80:
            java.lang.String r3 = r3.getProfileImage()
            if (r3 != 0) goto L87
            goto L88
        L87:
            r5 = r3
        L88:
            r2.getClass()
            java.lang.String r2 = "userName"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r2)
            java.lang.String r2 = "userImage"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r2)
            com.quizlet.data.model.v2 r2 = new com.quizlet.data.model.v2
            r2.<init>(r7, r4, r5)
            boolean r1 = r0.k(r1, r2)
            if (r1 == 0) goto L6e
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.Y.B(com.quizlet.quizletandroid.ui.startpage.nav2.Y, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x0084, code lost:
    
        r2 = r12.c1;
        r2 = kotlin.collections.B.j(r2.a, r2.b, r2.c, r2.d, r2.e, r2.f, r2.h);
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x009c, code lost:
    
        if (r2 == null) goto L33;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x00a2, code lost:
    
        if (r2.isEmpty() == false) goto L33;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00a5, code lost:
    
        r2 = r2.iterator();
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00ad, code lost:
    
        if (r2.hasNext() == false) goto L56;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00af, code lost:
    
        r4 = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o) r2.next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00b7, code lost:
    
        if (r4.a == false) goto L60;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00bb, code lost:
    
        if (r4.b != false) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00bd, code lost:
    
        r2 = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.m(new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.v(r12.t.a()));
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x00ce, code lost:
    
        r2 = com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.q.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x00ea, code lost:
    
        r2 = com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.q.a;
     */
    /* JADX WARN: Path cross not found for [B:17:0x0064, B:20:0x006b], limit reached: 59 */
    /* JADX WARN: Path cross not found for [B:20:0x006b, B:17:0x0064], limit reached: 59 */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00df A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00e0  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00f0  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:40:0x00bd -> B:47:0x00ea). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:45:0x00e0 -> B:46:0x00e4). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object C(com.quizlet.quizletandroid.ui.startpage.nav2.Y r12, kotlin.jvm.functions.Function1 r13, kotlin.coroutines.jvm.internal.c r14) {
        /*
            Method dump skipped, instructions count: 243
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.Y.C(com.quizlet.quizletandroid.ui.startpage.nav2.Y, kotlin.jvm.functions.Function1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final List D(Y y, List list, com.quizlet.quizletandroid.ui.startpage.nav2.model.P p) {
        y.getClass();
        return (list == null || list.isEmpty()) ? new ArrayList() : kotlin.jvm.internal.O.b(CollectionsKt.y0(F(G(list), p, null)));
    }

    public static final Map E(Y y, List list) {
        y.getClass();
        ArrayList arrayListE = CollectionsKt.E(list, 2);
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(arrayListE, 10));
        Iterator it2 = arrayListE.iterator();
        int i = 0;
        while (it2.hasNext()) {
            Object next = it2.next();
            int i2 = i + 1;
            if (i < 0) {
                kotlin.collections.B.p();
                throw null;
            }
            arrayList.add(new Pair(Integer.valueOf(i2), kotlin.jvm.internal.O.b(CollectionsKt.y0((List) next))));
            i = i2;
        }
        return kotlin.collections.V.k(arrayList);
    }

    public static ArrayList F(ArrayList arrayList, com.quizlet.quizletandroid.ui.startpage.nav2.model.P p, AbstractC3603d6 abstractC3603d6) {
        return CollectionsKt.c0(kotlin.collections.A.b(new com.quizlet.quizletandroid.ui.startpage.nav2.model.O(p, abstractC3603d6)), arrayList);
    }

    public static ArrayList G(List list) {
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
        int i = 0;
        for (Object obj : list) {
            int i2 = i + 1;
            if (i < 0) {
                kotlin.collections.B.p();
                throw null;
            }
            AbstractC4707c abstractC4707c = (AbstractC4707c) obj;
            abstractC4707c.a = i2 != list.size();
            arrayList.add(abstractC4707c);
            i = i2;
        }
        return arrayList;
    }

    public static C4905y K(io.reactivex.rxjava3.core.i iVar, androidx.lifecycle.Y y) {
        W w = new W(y, 2);
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        iVar.getClass();
        C4905y c4905y = new C4905y(new C4905y(new io.reactivex.rxjava3.internal.operators.observable.C(iVar, w, bVar), new W(y, 3), 0), new C4731v(y, 0), 1);
        Intrinsics.checkNotNullExpressionValue(c4905y, "doFinally(...)");
        return c4905y;
    }

    public final List H(List list) {
        DBUser dBUser;
        return (list.isEmpty() || ((com.quizlet.quizletandroid.ui.startpage.nav2.model.C) CollectionsKt.L(list)).g().isEmpty() || ((dBUser = this.g.r) != null && dBUser.getSelfIdentifiedUserType() == 1)) ? new ArrayList() : kotlin.jvm.internal.O.b(CollectionsKt.y0(F(G(list), com.quizlet.quizletandroid.ui.startpage.nav2.model.P.d, ((com.quizlet.quizletandroid.ui.startpage.nav2.model.C) CollectionsKt.L(list)).h())));
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x00fc  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object I(kotlin.coroutines.jvm.internal.c r14) {
        /*
            Method dump skipped, instructions count: 352
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.Y.I(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void J(boolean z) {
        int i = 0;
        int i2 = 1;
        io.reactivex.rxjava3.internal.observers.h hVarD = B7.d(K(this.v1, this.C), null, null, new C4730u(this, 2), 3);
        Intrinsics.checkNotNullParameter(hVarD, "<this>");
        A(hVarD);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new M(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new I(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new T(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new K(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new F(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new B(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new Q(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4754z(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4752x(this, z, null), 3);
        io.reactivex.rxjava3.internal.operators.single.g gVarG = this.f.u().g(C4694c.h);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        androidx.lifecycle.Y y = this.L;
        io.reactivex.rxjava3.internal.operators.single.e eVar = new io.reactivex.rxjava3.internal.operators.single.e(new io.reactivex.rxjava3.internal.operators.single.d(new io.reactivex.rxjava3.internal.operators.single.d(gVarG, new W(y, i), i2), new W(y, i2), i), new C4731v(y, 1), i2);
        Intrinsics.checkNotNullExpressionValue(eVar, "doFinally(...)");
        io.reactivex.rxjava3.internal.observers.e eVarB = B7.b(eVar, new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, timber.log.c.a, timber.log.a.class, "e", "e(Ljava/lang/Throwable;)V", 0, 26), new C4730u(this, i));
        Intrinsics.checkNotNullParameter(eVarB, "<this>");
        A(eVarB);
        Boolean bool = Boolean.TRUE;
        this.M.j(bool);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new L(this, null), 3);
        this.W.j(bool);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new D(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C(this, null), 3);
        C3 c3 = (C3) this.l.b;
        Intrinsics.checkNotNullExpressionValue(io.reactivex.rxjava3.core.a.d(new io.reactivex.rxjava3.internal.operators.observable.Y(((com.quizlet.infra.legacysyncengine.datasources.n) c3.b).d()), new io.reactivex.rxjava3.internal.operators.observable.Y(((com.quizlet.features.infra.studysetting.datasource.a) c3.c).d())), "mergeArray(...)");
    }

    @Override // com.quizlet.viewmodel.a, com.quizlet.viewmodel.b, androidx.lifecycle.w0
    public final void z() {
        C3 c3 = (C3) this.l.b;
        ((com.quizlet.infra.legacysyncengine.datasources.n) c3.b).a((C4693b) c3.i);
        C4693b c4693b = (C4693b) c3.j;
        com.quizlet.features.infra.studysetting.datasource.a aVar = (com.quizlet.features.infra.studysetting.datasource.a) c3.c;
        aVar.a(c4693b);
        aVar.g();
        ((io.reactivex.rxjava3.subjects.r) c3.k).onSuccess(Unit.a);
        super.z();
    }
}
