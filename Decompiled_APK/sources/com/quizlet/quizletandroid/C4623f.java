package com.quizlet.quizletandroid;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.Braze;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.authentication.SignUpWallEventLogger;
import com.quizlet.eventlogger.features.home.HomeEdgyEventLogger;
import com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger;
import com.quizlet.eventlogger.features.revisioncenter.RevisionCenterLogger;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger;
import com.quizlet.eventlogger.features.study.StudySessionQuestionEventLogger;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.generated.enums.I0;
import com.quizlet.quizletandroid.ui.startpage.nav2.C4693b;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4721q;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* renamed from: com.quizlet.quizletandroid.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4623f implements dagger.internal.c {
    public final u a;
    public final C4624g b;
    public final int c;

    public C4623f(u uVar, C4624g c4624g, int i) {
        this.a = uVar;
        this.b = c4624g;
        this.c = i;
    }

    @Override // javax.inject.a
    public final Object get() {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        u uVar = this.a;
        C4624g c4624g = this.b;
        int i = this.c;
        switch (i) {
            case 0:
                return new dagger.hilt.android.internal.lifecycle.h();
            case 1:
                com.google.mlkit.common.sdkinternal.model.a aVar = c4624g.a;
                return new com.quizlet.usecase.a(5);
            case 2:
                io.reactivex.rxjava3.core.o oVarL = com.quizlet.featuregate.injection.a.l();
                io.reactivex.rxjava3.core.o oVarJ = com.quizlet.featuregate.injection.a.j();
                androidx.work.impl.model.c cVarM0 = uVar.m0();
                com.quizlet.infra.legacysyncengine.managers.d dVar = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
                EventLogger eventLogger = (EventLogger) uVar.l0.get();
                SharedPreferences sharedPreferencesB0 = uVar.B0();
                com.quizlet.features.infra.basestudy.manager.d dVar2 = (com.quizlet.features.infra.basestudy.manager.d) uVar.D1.get();
                c4624g.getClass();
                u uVar2 = c4624g.b;
                com.quizlet.data.interactor.course.a aVar2 = new com.quizlet.data.interactor.course.a((Braze) uVar2.W0.get());
                Context context = uVar2.q();
                Intrinsics.checkNotNullParameter(context, "context");
                SharedPreferences sharedPreferences = context.getSharedPreferences("BRAZE_EVENT_SHARED_PREF", 0);
                Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
                S6.c(sharedPreferences);
                com.quizlet.quizletandroid.braze.events.b bVar = new com.quizlet.quizletandroid.braze.events.b(aVar2, new com.quizlet.db.b(sharedPreferences, 2), uVar2.l0());
                com.quizlet.quizletandroid.interactor.m getAllStudySetsCardWithCreatorUseCase = new com.quizlet.quizletandroid.interactor.m(uVar2.j(), (com.quizlet.infra.legacysyncengine.net.c) uVar2.Q.get(), new assistantMode.utils.studiableMetadata.b(29), com.quizlet.featuregate.injection.a.d());
                com.quizlet.infra.legacysyncengine.net.c loader = (com.quizlet.infra.legacysyncengine.net.c) uVar2.Q.get();
                com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager = (com.quizlet.infra.legacysyncengine.managers.d) uVar2.Z.get();
                Intrinsics.checkNotNullParameter(loader, "loader");
                Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
                com.quizlet.infra.legacysyncengine.datasources.n folderDataSource = new com.quizlet.infra.legacysyncengine.datasources.n(loggedInUserManager.e.getPersonId(), loader);
                com.quizlet.infra.legacysyncengine.net.c loader2 = (com.quizlet.infra.legacysyncengine.net.c) uVar2.Q.get();
                com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager2 = (com.quizlet.infra.legacysyncengine.managers.d) uVar2.Z.get();
                Intrinsics.checkNotNullParameter(loader2, "loader");
                Intrinsics.checkNotNullParameter(loggedInUserManager2, "loggedInUserManager");
                com.quizlet.features.infra.studysetting.datasource.a classDataSource = new com.quizlet.features.infra.studysetting.datasource.a(loader2, loggedInUserManager2.e.getPersonId(), 4);
                com.quizlet.data.repository.set.f recommendedSetRepository = uVar2.T0();
                androidx.work.impl.model.c dispatcher = u.v();
                org.slf4j.b logger = AbstractC4178x.o((org.slf4j.a) uVar2.Y.get(), "loggerFactory", com.quizlet.data.interactor.set.c.class, "getLogger(...)");
                Intrinsics.checkNotNullParameter(recommendedSetRepository, "recommendedSetRepository");
                Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
                Intrinsics.checkNotNullParameter(logger, "logger");
                com.quizlet.data.interactor.set.c recommendedSetsUseCase = new com.quizlet.data.interactor.set.c();
                recommendedSetsUseCase.a = recommendedSetRepository;
                recommendedSetsUseCase.b = dispatcher;
                recommendedSetsUseCase.c = logger;
                com.quizlet.data.repository.explanations.myexplanations.a getMyExplanationsUseCase = new com.quizlet.data.repository.explanations.myexplanations.a(uVar2.x0(), u.v());
                com.google.firebase.messaging.p achievementsStreaksUseCase = c4624g.a();
                com.google.firebase.crashlytics.internal.settings.b checkNotesEligibilityUseCase = c4624g.b();
                com.onetrust.otpublishers.headless.UI.fragment.q getRecentsStudyNotesUseCase = new com.onetrust.otpublishers.headless.UI.fragment.q(uVar2.E0());
                assistantMode.utils.studiableMetadata.b userMapper = new assistantMode.utils.studiableMetadata.b(29);
                Intrinsics.checkNotNullParameter(getAllStudySetsCardWithCreatorUseCase, "getAllStudySetsCardWithCreatorUseCase");
                Intrinsics.checkNotNullParameter(folderDataSource, "folderDataSource");
                Intrinsics.checkNotNullParameter(classDataSource, "classDataSource");
                Intrinsics.checkNotNullParameter(recommendedSetsUseCase, "recommendedSetsUseCase");
                Intrinsics.checkNotNullParameter(getMyExplanationsUseCase, "getMyExplanationsUseCase");
                Intrinsics.checkNotNullParameter(achievementsStreaksUseCase, "achievementsStreaksUseCase");
                Intrinsics.checkNotNullParameter(checkNotesEligibilityUseCase, "checkNotesEligibilityUseCase");
                Intrinsics.checkNotNullParameter(getRecentsStudyNotesUseCase, "getRecentsStudyNotesUseCase");
                Intrinsics.checkNotNullParameter(userMapper, "userMapper");
                C3 c3 = new C3();
                c3.a = getAllStudySetsCardWithCreatorUseCase;
                c3.b = folderDataSource;
                c3.c = classDataSource;
                c3.d = recommendedSetsUseCase;
                c3.e = getMyExplanationsUseCase;
                c3.f = achievementsStreaksUseCase;
                c3.g = checkNotesEligibilityUseCase;
                c3.h = getRecentsStudyNotesUseCase;
                C4693b c4693b = new C4693b();
                c3.i = c4693b;
                C4693b c4693b2 = new C4693b();
                c3.j = c4693b2;
                c3.k = Z.f("create(...)");
                folderDataSource.e(c4693b);
                classDataSource.e(c4693b2);
                androidx.work.impl.model.e eVar = new androidx.work.impl.model.e(c3, uVar2.m0());
                AbstractC5040y dispatcher2 = com.quizlet.featuregate.injection.a.d();
                Intrinsics.checkNotNullParameter(dispatcher2, "dispatcher");
                com.quizlet.data.repository.login.a feature = new com.quizlet.data.repository.login.a(dispatcher2, com.quizlet.generated.enums.H.UNITED_STATES, 12);
                Intrinsics.checkNotNullParameter(feature, "feature");
                com.quizlet.offline.managers.b bVar2 = (com.quizlet.offline.managers.b) uVar.d1.get();
                androidx.compose.foundation.text.input.internal.u uVar3 = new androidx.compose.foundation.text.input.internal.u(uVar2.T0(), u.v());
                com.quizlet.featuregate.features.home.a aVar3 = new com.quizlet.featuregate.features.home.a();
                com.lyft.android.scissors.b bVarD = c4624g.d();
                com.lyft.android.scissors.b bVar3 = new com.lyft.android.scissors.b((com.quizlet.infra.legacysyncengine.net.f) uVar2.U.get());
                Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
                com.google.mlkit.common.sdkinternal.model.a aVar4 = new com.google.mlkit.common.sdkinternal.model.a(26);
                C4721q c4721q = (C4721q) c4624g.f.get();
                HomeEdgyEventLogger homeEdgyEventLogger = new HomeEdgyEventLogger((EventLogger) uVar2.l0.get());
                EventLogger eventLogger2 = (EventLogger) uVar2.l0.get();
                Intrinsics.checkNotNullParameter(eventLogger2, "eventLogger");
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.a aVar5 = new com.quizlet.quizletandroid.ui.startpage.nav2.logging.a(eventLogger2);
                androidx.work.impl.model.c cVarM02 = uVar2.m0();
                com.lyft.android.scissors.b bVarG0 = uVar2.G0();
                com.quizlet.infra.contracts.growthbook.a aVar6 = (com.quizlet.infra.contracts.growthbook.a) uVar2.y0.get();
                return new Y(oVarL, oVarJ, cVarM0, dVar, eventLogger, sharedPreferencesB0, dVar2, bVar, eVar, feature, bVar2, uVar3, aVar3, bVarD, bVar3, aVar4, c4721q, homeEdgyEventLogger, aVar5, new com.quizlet.quizletandroid.ui.startpage.nav2.usecases.k(cVarM02, bVarG0, AbstractC4178x.i(aVar6, "growthBook", "onboarding_ell_home_section_android", aVar6)), new RevisionCenterLogger((EventLogger) uVar2.l0.get()), c4624g.b(), new com.quizlet.shared.usecase.folderstudymaterials.b(25), new com.quizlet.quizletandroid.ui.globalnav.logging.a((EventLogger) uVar2.l0.get()), uVar.l0());
            case 3:
                return new C4721q();
            case 4:
                StudySessionQuestionEventLogger.Factory factory = new StudySessionQuestionEventLogger.Factory((EventLogger) c4624g.b.l0.get());
                Intrinsics.checkNotNullParameter(factory, "factory");
                return factory.a();
            case 5:
                return new SetPagePerformanceLogger((com.google.firebase.perf.b) uVar.J.get());
            case 6:
                return new com.quizlet.features.match.studyengine.f(new com.google.android.material.floatingactionbutton.c(c4624g.h()));
            case 7:
                com.quizlet.billing.register.a aVarJ1 = uVar.j1();
                UserInfoCache userInfoCacheL0 = uVar.l0();
                com.facebook.z zVarD1 = uVar.d1();
                SearchEventLogger searchEventLogger = (SearchEventLogger) uVar.G1.get();
                com.facebook.z zVarF0 = uVar.F0();
                androidx.work.impl.model.c cVarM03 = uVar.m0();
                com.quizlet.data.repository.activitycenter.b bVar4 = new com.quizlet.data.repository.activitycenter.b(new com.google.firebase.heartbeatinfo.e(26), new com.google.android.material.shape.e(26));
                com.quizlet.featuregate.features.studymodes.learn.a aVar7 = new com.quizlet.featuregate.features.studymodes.learn.a(2);
                com.quizlet.offline.managers.b bVar5 = (com.quizlet.offline.managers.b) uVar.d1.get();
                com.quizlet.infra.legacysyncengine.net.f fVar = (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get();
                com.quizlet.infra.legacysyncengine.net.c cVar = (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get();
                com.quizlet.data.repository.user.a aVarO = uVar.O();
                StudyModeEventLogger.Factory factoryJ = c4624g.j();
                u uVar4 = c4624g.b;
                return new com.quizlet.features.infra.basestudy.manager.a(aVarJ1, userInfoCacheL0, zVarD1, searchEventLogger, zVarF0, cVarM03, bVar4, aVar7, bVar5, fVar, cVar, aVarO, factoryJ, new com.quizlet.data.repository.qclass.c(uVar4.B0(), uVar4.l0()), (com.quizlet.features.infra.basestudy.manager.d) uVar.D1.get(), c4624g.c(), (StudySessionQuestionEventLogger) c4624g.h.get());
            case 8:
                return new com.quizlet.quizletandroid.ui.studymodes.grader.b(dagger.internal.a.a(c4624g.l), dagger.internal.a.a(c4624g.m));
            case 9:
                assistantMode.refactored.d studyEngineFactory = assistantMode.refactored.d.a;
                Intrinsics.checkNotNullParameter(studyEngineFactory, "studyEngineFactory");
                return new com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b();
            case 10:
                com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.d qTestGeneratorFactory = com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.d.a;
                Intrinsics.checkNotNullParameter(qTestGeneratorFactory, "qTestGeneratorFactory");
                return new com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.c();
            case 11:
                u uVar5 = c4624g.b;
                UserInfoCache userInfoCache = uVar5.l0();
                com.quizlet.infra.legacysyncengine.managers.i modelSaveManager = (com.quizlet.infra.legacysyncengine.managers.i) uVar5.S.get();
                Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
                Intrinsics.checkNotNullParameter(modelSaveManager, "modelSaveManager");
                Intrinsics.checkNotNullParameter(new com.quizlet.quizletandroid.ui.common.adapter.c(), "factory");
                return new com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a(userInfoCache, modelSaveManager);
            case 12:
                com.quizlet.data.interactor.set.c cVarE = c4624g.e();
                StudyModeMeteringEventLogger studyModeMeteringEventLoggerK = c4624g.k();
                com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.y yVar = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.y) c4624g.r.get();
                AbstractC5040y abstractC5040yD = com.quizlet.featuregate.injection.a.d();
                s factory2 = (s) uVar.W1.get();
                Intrinsics.checkNotNullParameter(factory2, "factory");
                I0 i0 = I0.BLOCKS;
                u uVar6 = factory2.a.a;
                com.quizlet.data.repository.folderset.c cVar2 = new com.quizlet.data.repository.folderset.c(uVar6.m0(), uVar6.k(), i0);
                s factory3 = (s) uVar.W1.get();
                Intrinsics.checkNotNullParameter(factory3, "factory");
                I0 i02 = I0.BLAST_SINGLE_PLAYER;
                u uVar7 = factory3.a.a;
                return new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G(cVarE, studyModeMeteringEventLoggerK, yVar, abstractC5040yD, cVar2, new com.quizlet.data.repository.folderset.c(uVar7.m0(), uVar7.k(), i02), new com.quizlet.shared.usecase.folderstudymaterials.a(26), uVar.g0());
            case 13:
                return new com.quizlet.infra.legacysyncengine.datasources.factory.b((com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get(), uVar.Z(), uVar.j(), uVar.d1());
            case 14:
                Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
                return new com.quizlet.local.cache.g(5L);
            case 15:
                long j = uVar.j();
                androidx.work.impl.model.c cVarM04 = uVar.m0();
                u uVar8 = c4624g.b;
                return new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.y(j, cVarM04, new com.quizlet.data.interactor.metering.b(uVar8.w0(), uVar8.z0()), c4624g.k(), com.quizlet.featuregate.injection.a.d());
            case 16:
                Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
                return new com.quizlet.local.cache.g(5L);
            case 17:
                return new com.quizlet.features.setpage.offline.k(uVar.m0(), new com.quizlet.featuregate.features.folder.e(uVar.m0(), 1), (com.quizlet.offline.managers.b) uVar.d1.get(), new com.google.firebase.messaging.p((EventLogger) uVar.l0.get()), com.quizlet.featuregate.injection.a.d());
            case 18:
                io.ktor.client.plugins.api.d dVar3 = new io.ktor.client.plugins.api.d(c4624g.b.l1(), u.v(), (com.quizlet.cache.a) c4624g.t.get());
                com.quizlet.data.repository.explanations.textbook.a aVarG = c4624g.g();
                u uVar9 = c4624g.b;
                return new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s(dVar3, new com.quizlet.remote.model.notes.e(aVarG, new com.quizlet.data.repository.widget.b(new com.quizlet.quizletandroid.ui.group.data.b((com.quizlet.infra.legacysyncengine.net.c) uVar9.Q.get(), uVar9.j(), 1)), new com.quizlet.data.repository.searchexplanations.c(new com.quizlet.quizletandroid.ui.group.data.b((com.quizlet.infra.legacysyncengine.net.c) uVar9.Q.get(), uVar9.j(), 1)), new androidx.compose.foundation.text.input.internal.u(new com.quizlet.quizletandroid.ui.group.data.b((com.quizlet.infra.legacysyncengine.net.c) uVar9.Q.get(), uVar9.j(), 2)), com.quizlet.featuregate.injection.a.d()), new androidx.work.impl.model.v(uVar9.d1(), c4624g.g()), new com.quizlet.features.infra.basestudy.usecase.b(new com.quizlet.data.repository.studysetwithcreatorinclass.g(uVar9.l0(), (com.quizlet.infra.legacysyncengine.net.c) uVar9.Q.get(), uVar9.o1(), new com.quizlet.featuregate.features.studymodes.learn.a(2), uVar9.m0()), new com.google.firebase.perf.logging.b(26), uVar9.m0(), new com.quizlet.data.interactor.metering.b(uVar9.w0(), uVar9.z0()), (com.quizlet.infra.legacysyncengine.managers.d) uVar9.Z.get()), uVar.m0(), new com.quizlet.data.interactor.metering.b(uVar9.w0(), uVar9.z0()), new SignUpWallEventLogger((EventLogger) uVar9.l0.get()), (SetPagePerformanceLogger) c4624g.i.get(), com.quizlet.featuregate.injection.a.d(), new com.google.mlkit.vision.documentscanner.internal.c(uVar9.D0()));
            case 19:
                return new com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.e();
            default:
                throw new AssertionError(i);
        }
    }
}
