package com.quizlet.features.infra.basestudy.manager;

import android.content.SharedPreferences;
import androidx.lifecycle.m0;
import com.facebook.z;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.study.StudySessionQuestionEventLogger;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.features.infra.basestudy.data.models.x;
import com.quizlet.generated.enums.A1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final com.quizlet.billing.register.a a;
    public final UserInfoCache b;
    public final z c;
    public final SearchEventLogger d;
    public final z e;
    public final androidx.work.impl.model.c f;
    public final com.quizlet.data.repository.activitycenter.b g;
    public final com.quizlet.featuregate.features.studymodes.learn.a h;
    public final com.quizlet.offline.managers.b i;
    public final com.quizlet.infra.legacysyncengine.net.f j;
    public final com.quizlet.infra.legacysyncengine.net.c k;
    public final com.quizlet.data.repository.user.a l;
    public final StudyModeEventLogger.Factory m;
    public final d n;
    public final com.quizlet.infra.legacysyncengine.features.properties.d o;
    public final StudySessionQuestionEventLogger p;
    public final com.quizlet.ads.d q;
    public f r;

    public a(com.quizlet.billing.register.a modeSharedPreferencesManager, UserInfoCache userInfoCache, z setInSelectedTermsModeCache, SearchEventLogger searchEventLogger, z offlineSettingsState, androidx.work.impl.model.c userProperties, com.quizlet.data.repository.activitycenter.b shareStatusManager, com.quizlet.featuregate.features.studymodes.learn.a defaultStudyPathConfiguration, com.quizlet.offline.managers.b offlineStateManager, com.quizlet.infra.legacysyncengine.net.f syncDispatcher, com.quizlet.infra.legacysyncengine.net.c loader, com.quizlet.data.repository.user.a gaLogger, StudyModeEventLogger.Factory studyModeEventLoggerFactory, com.quizlet.data.repository.qclass.c rateUsSessionManagerFactory, d studyFunnelEventManager, com.quizlet.infra.legacysyncengine.features.properties.d studySetProperties, StudySessionQuestionEventLogger studySessionQuestionEventLogger) {
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
        Intrinsics.checkNotNullParameter(studyModeEventLoggerFactory, "studyModeEventLoggerFactory");
        Intrinsics.checkNotNullParameter(rateUsSessionManagerFactory, "rateUsSessionManagerFactory");
        Intrinsics.checkNotNullParameter(studyFunnelEventManager, "studyFunnelEventManager");
        Intrinsics.checkNotNullParameter(studySetProperties, "studySetProperties");
        Intrinsics.checkNotNullParameter(studySessionQuestionEventLogger, "studySessionQuestionEventLogger");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.a = modeSharedPreferencesManager;
        this.b = userInfoCache;
        this.c = setInSelectedTermsModeCache;
        this.d = searchEventLogger;
        this.e = offlineSettingsState;
        this.f = userProperties;
        this.g = shareStatusManager;
        this.h = defaultStudyPathConfiguration;
        this.i = offlineStateManager;
        this.j = syncDispatcher;
        this.k = loader;
        this.l = gaLogger;
        this.m = studyModeEventLoggerFactory;
        this.n = studyFunnelEventManager;
        this.o = studySetProperties;
        this.p = studySessionQuestionEventLogger;
        long personId = ((UserInfoCache) rateUsSessionManagerFactory.c).getPersonId();
        this.q = personId > 0 ? new com.quizlet.ads.d(personId, (SharedPreferences) rateUsSessionManagerFactory.b) : null;
    }

    public final f a(m0 savedStateHandle) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        f fVar = this.r;
        if (fVar != null) {
            return fVar;
        }
        x xVarB = AbstractC3249r5.b(savedStateHandle);
        StudyModeEventLogger.Factory factory = this.m;
        A1 a1 = xVarB.g;
        StudyModeEventLogger studyModeEventLoggerA = factory.a(a1);
        Intrinsics.checkNotNullExpressionValue(studyModeEventLoggerA, "create(...)");
        f fVar2 = new f(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, studyModeEventLoggerA, this.q, xVarB.c, xVarB.a, xVarB.b, xVarB.f, a1, xVarB.d, xVarB.e, this.n, this.o, this.p, xVarB.h);
        this.r = fVar2;
        return fVar2;
    }
}
