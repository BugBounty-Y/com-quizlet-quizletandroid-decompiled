package com.quizlet.features.infra.basestudy.manager;

import androidx.compose.ui.node.B;
import com.facebook.z;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3258s5;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.study.StudySessionQuestionEventLogger;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.eventlogger.model.StudyEventLog;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.C1;
import com.quizlet.generated.enums.G1;
import com.quizlet.infra.legacysyncengine.net.request.g;
import com.quizlet.offline.managers.i;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class f {
    public final UserInfoCache a;
    public final z b;
    public final SearchEventLogger c;
    public final androidx.work.impl.model.c d;
    public final com.quizlet.data.repository.activitycenter.b e;
    public final com.quizlet.featuregate.features.studymodes.learn.a f;
    public final com.quizlet.infra.legacysyncengine.net.f g;
    public final com.quizlet.data.repository.user.a h;
    public final StudyModeEventLogger i;
    public final com.quizlet.ads.d j;
    public boolean k;
    public final StudyableModelData l;
    public final long m;
    public final ArrayList n;
    public final A1 o;
    public final String p;
    public final int q;
    public final d r;
    public final com.quizlet.infra.legacysyncengine.features.properties.d s;
    public final String t;
    public final long u;
    public final G1 v;
    public final io.reactivex.rxjava3.subjects.b w;
    public final com.quizlet.features.infra.basestudy.data.models.dataproviders.a x;
    public com.quizlet.features.infra.studysetting.managers.a y;
    public final s0 z;

    public f(com.quizlet.billing.register.a modeSharedPreferencesManager, UserInfoCache userInfoCache, z setInSelectedTermsModeCache, SearchEventLogger searchEventLogger, z offlineSettingsState, androidx.work.impl.model.c userProperties, com.quizlet.data.repository.activitycenter.b shareStatusManager, com.quizlet.featuregate.features.studymodes.learn.a defaultStudyPathConfiguration, com.quizlet.offline.managers.b offlineStateManager, com.quizlet.infra.legacysyncengine.net.f syncDispatcher, com.quizlet.infra.legacysyncengine.net.c loader, com.quizlet.data.repository.user.a gaLogger, StudyModeEventLogger studyModeEventLogger, com.quizlet.ads.d dVar, boolean z, StudyableModelData studyableModelData, long j, ArrayList arrayList, A1 studyModeType, String screenName, int i, d studyFunnelEventManager, com.quizlet.infra.legacysyncengine.features.properties.d studySetProperties, StudySessionQuestionEventLogger studySessionQuestionEventLogger, Boolean bool) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(modeSharedPreferencesManager, "modeSharedPreferencesManager");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(setInSelectedTermsModeCache, "setInSelectedTermsModeCache");
        Intrinsics.checkNotNullParameter(searchEventLogger, "searchEventLogger");
        Intrinsics.checkNotNullParameter(offlineSettingsState, "offlineSettingsState");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(shareStatusManager, "shareStatusManager");
        Intrinsics.checkNotNullParameter(defaultStudyPathConfiguration, "defaultStudyPathConfiguration");
        Intrinsics.checkNotNullParameter(offlineStateManager, "offlineStateManager");
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(gaLogger, "gaLogger");
        Intrinsics.checkNotNullParameter(studyModeEventLogger, "studyModeEventLogger");
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
        Intrinsics.checkNotNullParameter(screenName, "screenName");
        Intrinsics.checkNotNullParameter(studyFunnelEventManager, "studyFunnelEventManager");
        Intrinsics.checkNotNullParameter(studySetProperties, "studySetProperties");
        Intrinsics.checkNotNullParameter(studySessionQuestionEventLogger, "studySessionQuestionEventLogger");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.a = userInfoCache;
        this.b = setInSelectedTermsModeCache;
        this.c = searchEventLogger;
        this.d = userProperties;
        this.e = shareStatusManager;
        this.f = defaultStudyPathConfiguration;
        this.g = syncDispatcher;
        this.h = gaLogger;
        this.i = studyModeEventLogger;
        this.j = dVar;
        this.k = z;
        this.l = studyableModelData;
        this.m = j;
        this.n = arrayList;
        this.o = studyModeType;
        this.p = screenName;
        this.q = i;
        this.r = studyFunnelEventManager;
        this.s = studySetProperties;
        String strF = B.f("toString(...)");
        this.t = strF;
        long jK = studyableModelData.k();
        this.u = jK;
        G1 studyableType = studyableModelData.getStudyableType();
        this.v = studyableType;
        io.reactivex.rxjava3.subjects.b bVar = new io.reactivex.rxjava3.subjects.b();
        Intrinsics.checkNotNullExpressionValue(bVar, "create(...)");
        this.w = bVar;
        com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVarB = AbstractC3258s5.b(userInfoCache.getPersonId(), studyableModelData, studyModeType, loader, new com.google.android.material.search.a(this, 19), arrayList, this.k);
        Intrinsics.checkNotNullExpressionValue(aVarB, "create(...)");
        this.x = aVarB;
        this.z = e0.c(null);
        studySessionQuestionEventLogger.b(strF);
        searchEventLogger.n(studyModeType, strF);
        studyModeEventLogger.b(strF, studyableType, Integer.valueOf(i), aVarB.C, Long.valueOf(jK), Long.valueOf(j), this.k, null, bool);
        if (studyableType == G1.SET) {
            List listSingletonList = Collections.singletonList(Long.valueOf(jK));
            Intrinsics.checkNotNullExpressionValue(listSingletonList, "singletonList(...)");
            ((i) offlineStateManager).b(offlineSettingsState, listSingletonList);
        }
    }

    public static final com.quizlet.features.infra.studysetting.managers.a a(f fVar, C1 c1) {
        s0 s0Var;
        Object value;
        fVar.getClass();
        com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = fVar.x;
        List list = aVar.D;
        if (list == null) {
            list = K.a;
        }
        long personId = fVar.a.getPersonId();
        StudyableModel studyableModel = aVar.f;
        Intrinsics.checkNotNullExpressionValue(studyableModel, "getStudyableModel(...)");
        com.quizlet.features.infra.studysetting.managers.a aVar2 = new com.quizlet.features.infra.studysetting.managers.a(fVar.g, list, personId, studyableModel, c1);
        fVar.y = aVar2;
        do {
            s0Var = fVar.z;
            value = s0Var.getValue();
        } while (!s0Var.k(value, aVar2));
        return aVar2;
    }

    public static void h(f fVar) {
        Integer numValueOf = Integer.valueOf(fVar.q);
        DBSession dBSession = fVar.x.C;
        long j = fVar.u;
        Long lValueOf = Long.valueOf(j);
        Long lValueOf2 = Long.valueOf(fVar.m);
        boolean z = fVar.k;
        c cVarC = fVar.r.c(j);
        fVar.i.c(fVar.t, fVar.v, numValueOf, dBSession, lValueOf, lValueOf2, z, null, cVarC != null ? cVarC.a : null);
    }

    public static void i(f fVar) {
        fVar.i.d(fVar.t, fVar.v, Integer.valueOf(fVar.q), fVar.x.C, Long.valueOf(fVar.u), Long.valueOf(fVar.m), fVar.k, null);
    }

    public static void j(f fVar, String nextAction, int i) {
        String str;
        if ((i & 2) != 0) {
            com.quizlet.features.infra.basestudy.data.models.logging.a[] aVarArr = com.quizlet.features.infra.basestudy.data.models.logging.a.a;
            str = "test_results_next_action_button_clicked";
        } else {
            str = "learn_next_action_button_clicked";
        }
        String action = str;
        fVar.getClass();
        Intrinsics.checkNotNullParameter(nextAction, "nextAction");
        Intrinsics.checkNotNullParameter(action, "action");
        Intrinsics.checkNotNullParameter("results", "screen");
        Integer numValueOf = Integer.valueOf(fVar.q);
        DBSession dBSession = fVar.x.C;
        long j = fVar.u;
        Long lValueOf = Long.valueOf(j);
        boolean z = fVar.k;
        StudyModeEventLogger studyModeEventLogger = fVar.i;
        Long lValueOf2 = (dBSession == null || dBSession.getId() <= 0) ? null : Long.valueOf(dBSession.getId());
        Long lValueOf3 = dBSession != null ? Long.valueOf(dBSession.getLocalId()) : null;
        if (j < 0) {
            lValueOf = null;
        }
        StudyEventLog.Companion companion = StudyEventLog.b;
        companion.getClass();
        Intrinsics.checkNotNullParameter(action, "action");
        Long l = lValueOf;
        Long l2 = lValueOf3;
        String studySessionId = fVar.t;
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        A1 modeType = studyModeEventLogger.b;
        Intrinsics.checkNotNullParameter(modeType, "modeType");
        G1 studyableType = fVar.v;
        Intrinsics.checkNotNullParameter(studyableType, "studyableType");
        studyModeEventLogger.a.v(StudyEventLog.Companion.b(companion, action, studySessionId, modeType, lValueOf2, l2, l, fVar.m, studyableType, z, numValueOf, "results", null, null, nextAction, null, 786432));
    }

    public static void k(f fVar, String screen, Boolean bool, int i) {
        if ((i & 4) != 0) {
            bool = null;
        }
        fVar.getClass();
        Intrinsics.checkNotNullParameter(screen, "screen");
        Integer numValueOf = Integer.valueOf(fVar.q);
        DBSession dBSession = fVar.x.C;
        Long lValueOf = Long.valueOf(fVar.u);
        Long lValueOf2 = Long.valueOf(fVar.m);
        Boolean boolValueOf = Boolean.valueOf(fVar.k);
        fVar.i.e(fVar.t, fVar.v, numValueOf, dBSession, lValueOf, lValueOf2, boolValueOf, screen, bool);
    }

    public final DBSession b() {
        long personId = this.a.getPersonId();
        boolean z = this.k;
        long jCurrentTimeMillis = System.currentTimeMillis();
        DBSession dBSession = new DBSession(personId, this.u, this.v, this.o, z, jCurrentTimeMillis);
        this.g.a(dBSession);
        return dBSession;
    }

    public final io.reactivex.rxjava3.subjects.b c() {
        com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = this.x;
        io.reactivex.rxjava3.subjects.f fVar = aVar.g;
        com.quizlet.eventlogger.e eVar = new com.quizlet.eventlogger.e(this, 6);
        g gVar = io.reactivex.rxjava3.internal.functions.d.e;
        fVar.f(eVar, gVar);
        J j = aVar.l;
        j.getClass();
        new C4887f(j, 5).u(new e(this, 1), gVar, io.reactivex.rxjava3.internal.functions.d.c);
        return this.w;
    }

    public final StudyEventLogData d() {
        long j = this.m;
        boolean z = this.k;
        return new StudyEventLogData(this.u, j, this.t, z);
    }

    public final DBStudySet e() {
        StudyableModel studyableModel = this.x.f;
        if (studyableModel instanceof DBStudySet) {
            return (DBStudySet) studyableModel;
        }
        return null;
    }

    public final p f() {
        if (this.v == G1.SET) {
            long j = this.u;
            if (j > 0 && e() != null) {
                com.quizlet.infra.legacysyncengine.features.properties.d dVar = this.s;
                com.quizlet.infra.legacysyncengine.features.properties.d.c(dVar, j);
                return this.e.g(this.d, dVar);
            }
        }
        return p.f(com.quizlet.features.infra.basestudy.data.models.shareset.a.d);
    }

    public final com.quizlet.features.infra.studysetting.managers.a g() {
        com.quizlet.features.infra.studysetting.managers.a aVar = this.y;
        if (aVar != null) {
            return aVar;
        }
        Object objB = this.f.a(this.d).e(new com.google.mlkit.vision.documentscanner.internal.c(this, 17)).b();
        Intrinsics.checkNotNullExpressionValue(objB, "blockingGet(...)");
        return (com.quizlet.features.infra.studysetting.managers.a) objB;
    }

    public final void l(String screen) {
        Intrinsics.checkNotNullParameter(screen, "screen");
        this.i.f(this.t, this.v, Integer.valueOf(this.q), this.x.C, Long.valueOf(this.u), Long.valueOf(this.m), Boolean.valueOf(this.k), screen);
    }

    public final void m() {
        this.x.e();
    }

    public final void n(boolean z) {
        this.k = z;
        com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = this.x;
        aVar.h.b(Boolean.valueOf(z));
        G1 g1 = G1.SET;
        G1 g12 = this.v;
        if (g12 != g1) {
            throw new UnsupportedOperationException("Non-set studyable models are not implemented yet");
        }
        this.b.c(this.u, g12, this.k);
    }
}
