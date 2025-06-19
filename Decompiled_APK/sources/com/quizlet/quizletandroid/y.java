package com.quizlet.quizletandroid;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ShortcutManager;
import androidx.compose.foundation.gestures.l1;
import androidx.compose.ui.node.V;
import androidx.datastore.core.InterfaceC1076h;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import com.appsflyer.attribution.RequestError;
import com.braze.Braze;
import com.comscore.android.ConnectivityType;
import com.comscore.android.util.AndroidTcfDataLoader;
import com.comscore.streaming.ContentType;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.facebook.C1544a;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.measurement.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.ads.Zh;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.android.gms.measurement.internal.J;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.data.model.C4184z;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.edgy.ui.viewmodel.C4204e;
import com.quizlet.edgy.ui.viewmodel.M;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.achievements.AchievementsEventLogger;
import com.quizlet.eventlogger.features.authentication.SignUpWallEventLogger;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogger;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLogger;
import com.quizlet.eventlogger.features.qincentives.QIncentivesEventLogger;
import com.quizlet.eventlogger.features.revisioncenter.RevisionCenterLogger;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger;
import com.quizlet.eventlogger.features.study.StudyFunnelEventLogger;
import com.quizlet.eventlogger.features.study.StudySessionQuestionEventLogger;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.features.flashcards.S;
import com.quizlet.features.folders.viewmodel.N;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.features.setpage.viewmodel.SetPageMobileWebViewModel;
import com.quizlet.features.settings.viewmodels.C4444b;
import com.quizlet.features.settings.viewmodels.C4446d;
import com.quizlet.features.settings.viewmodels.C4449g;
import com.quizlet.features.settings.viewmodels.C4451i;
import com.quizlet.generated.enums.A1;
import com.quizlet.learn.viewmodel.C4556c;
import com.quizlet.local.datastore.preferences.C4567d;
import com.quizlet.quizletandroid.ui.library.c0;
import com.quizlet.quizletandroid.ui.live.QuizletLiveViewModel;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4739h;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import com.quizlet.remote.service.InterfaceC4778e;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.O;

/* loaded from: classes3.dex */
public final class y implements dagger.internal.c {
    public final u a;
    public final C4624g b;
    public final z c;
    public final int d;

    public y(u uVar, C4624g c4624g, z zVar, int i) {
        this.a = uVar;
        this.b = c4624g;
        this.c = zVar;
        this.d = i;
    }

    /* JADX WARN: Type inference failed for: r3v58, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r4v34, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r4v97, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r5v82, types: [java.lang.Object, kotlin.k] */
    public final Object a() {
        C4624g c4624g = this.b;
        u uVar = this.a;
        z zVar = this.c;
        int i = this.d;
        switch (i) {
            case 0:
                return new com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate.e();
            case 1:
                return new com.quizlet.features.achievements.home.a((AchievementsEventLogger) zVar.e.get());
            case 2:
                return new AchievementsEventLogger((EventLogger) uVar.l0.get());
            case 3:
                return new com.quizlet.features.achievements.notification.f(zVar.c(), uVar.j(), zVar.d());
            case 4:
                return new com.quizlet.features.achievements.viewmodel.b(new com.onetrust.otpublishers.headless.Internal.Helper.h(26), zVar.H(), zVar.b(), dagger.internal.a.a(zVar.e), zVar.G(), zVar.a);
            case 5:
                return new com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a(zVar.e(), uVar.r1(), uVar.i());
            case 6:
                com.google.firebase.crashlytics.internal.settings.b bVarB = c4624g.b();
                l1 l1VarN = zVar.N();
                com.google.firebase.messaging.p pVarW = zVar.W();
                l1 l1VarJ = zVar.J();
                u uVar2 = zVar.b;
                C1608n c1608n = new C1608n(uVar2.l0(), uVar2.m0(), zVar.c.b(), uVar2.p1(), uVar2.w1());
                u uVar3 = zVar.b;
                return new com.quizlet.features.folders.addtofolder.viewmodel.m(bVarB, l1VarN, pVarW, l1VarJ, c1608n, new com.quizlet.features.folders.logging.e((EventLogger) uVar3.l0.get(), new StudyFunnelEventLogger((EventLogger) uVar3.l0.get()), (com.quizlet.infra.contracts.studyfunnel.a) uVar3.D1.get()), uVar.p1(), zVar.Q());
            case 7:
                return new com.quizlet.quizletandroid.ui.setpage.addset.c((com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get(), (com.quizlet.quizletandroid.util.a) uVar.y1.get());
            case 8:
                return new com.quizlet.features.infra.folder.menu.viewmodel.a(new com.quizlet.features.infra.folder.menu.viewmodel.m(uVar.d(), uVar.w1(), (FolderLogger) uVar.J1.get(), com.quizlet.featuregate.injection.a.d(), uVar.p1()));
            case 9:
                return new com.quizlet.ads.viewmodel.a(zVar.a, zVar.f());
            case 10:
                return new C4444b(zVar.a, zVar.O0(), zVar.G0());
            case 11:
                return new com.quizlet.quizletandroid.ui.usersettings.d(uVar.q(), com.quizlet.featuregate.injection.a.l(), com.quizlet.featuregate.injection.a.j(), (IQuizletApiClient) uVar.O.get(), uVar.s1(), (com.quizlet.infra.legacysyncengine.tasks.parse.f) uVar.F.get(), uVar.l0(), (com.quizlet.db.token.a) uVar.u.get(), (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get());
            case 12:
                return new C4446d(zVar.O0(), new com.quizlet.shared.usecase.srs.a(27), zVar.G0(), (com.quizlet.usecase.b) uVar.u1.get());
            case 13:
                return new com.quizlet.quizletandroid.ui.usersettings.viewmodels.c(zVar.a, (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get(), (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get());
            case 14:
                return new com.quizlet.features.folders.changetags.viewmodel.d(zVar.a, uVar.d(), (FolderLogger) uVar.J1.get());
            case 15:
                return new C4449g(zVar.a, zVar.O0(), zVar.G0());
            case 16:
                return new com.quizlet.explanations.textbook.chaptermenu.viewmodel.b();
            case 17:
                return new com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a(zVar.a, zVar.l(), new com.quizlet.quizletandroid.util.o(uVar.q()), (com.quizlet.offline.managers.b) uVar.d1.get(), new com.quizlet.data.interactor.achievements.f((com.quizlet.quizletandroid.interactor.t) zVar.b.Y0.get()), com.quizlet.featuregate.injection.a.i(), zVar.h0(), uVar.m0(), com.quizlet.featuregate.injection.a.k());
            case 18:
                return new com.quizlet.quizletandroid.ui.classcreation.i(zVar.q(), (com.quizlet.offline.managers.b) uVar.d1.get());
            case 19:
                return new com.quizlet.quizletandroid.ui.group.classuser.viewmodel.a(zVar.a, zVar.g0());
            case 20:
                return new com.quizlet.quizletandroid.ui.group.addclassset.viewmodel.a(zVar.m());
            case 21:
                u uVar4 = zVar.b;
                return new com.quizlet.features.infra.folder.create.coursefolder.viewmodel.e(new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i(new com.google.firebase.crashlytics.internal.settings.b(uVar4.W0()), zVar.s(), zVar.x(), zVar.D0(), uVar4.m0()), (FolderLogger) uVar.J1.get(), uVar.r());
            case EventType.WINDOW_STATE /* 22 */:
                return new com.quizlet.features.infra.folder.create.viewmodel.b(new J(uVar.G(), uVar.U0(), uVar.j(), com.quizlet.featuregate.injection.a.d()), (EventLogger) uVar.l0.get());
            case EventType.AUDIO /* 23 */:
                return new C4451i(zVar.a, zVar.O0(), new com.quizlet.shared.usecase.srs.a(27), zVar.G0());
            case EventType.VIDEO /* 24 */:
                return new com.quizlet.quizletandroid.ui.group.addclassset.viewmodel.b(zVar.m());
            case EventType.SUBS /* 25 */:
                androidx.work.impl.model.c cVarM0 = uVar.m0();
                com.quizlet.shared.usecase.folderstudymaterials.a aVarB = com.quizlet.featuregate.injection.a.b();
                com.quizlet.shared.usecase.folderstudymaterials.a aVarC = com.quizlet.featuregate.injection.a.c();
                EventLogger eventLogger = (EventLogger) c4624g.b.l0.get();
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                return new C4739h(cVarM0, aVarB, aVarC, new com.quizlet.quizletandroid.ui.startpage.nav2.logging.c(eventLogger), c4624g.b(), (FolderLogger) uVar.J1.get(), uVar.J0(), uVar.s());
            case EventType.CDN /* 26 */:
                return new com.quizlet.quizletandroid.ui.deeplinkinterstitial.i(zVar.v(), zVar.u(), zVar.t(), (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get(), uVar.a1());
            case 27:
                uVar.b.getClass();
                return new com.quizlet.utmhelper.d();
            case 28:
                return new com.quizlet.features.settings.viewmodels.k(zVar.a, zVar.y());
            case 29:
                return new com.quizlet.features.match.viewmodel.d(zVar.a, (com.quizlet.features.match.studyengine.f) c4624g.k.get(), zVar.w0());
            case 30:
                return new com.quizlet.diagrams.ui.i(zVar.z());
            case 31:
                return new C4204e(new com.google.firebase.crashlytics.internal.settings.b(zVar.b.U0()), zVar.M());
            case 32:
                return new com.quizlet.edgy.ui.viewmodel.w(zVar.A(), new com.google.firebase.crashlytics.internal.settings.b(zVar.b.W0()));
            case 33:
                return new M(new com.onetrust.otpublishers.headless.UI.fragment.q(zVar.b.W0()), new com.google.firebase.messaging.p(zVar.b.U0()), zVar.x(), zVar.w(), zVar.s(), zVar.r(), new com.quizlet.data.interactor.school.f(), zVar.p(), zVar.D0(), new com.quizlet.data.interactor.course.a((EventLogger) zVar.b.l0.get()));
            case 34:
                return new com.quizlet.quizletandroid.ui.setcreation.viewmodels.e(com.quizlet.featuregate.injection.a.m(), uVar.m0(), uVar.C0(), zVar.j(), zVar.K0());
            case 35:
                return new com.quizlet.features.folders.edittags.viewmodel.c(zVar.a, new com.quizlet.data.repository.qclass.c(uVar.G(), com.quizlet.featuregate.injection.a.d()), uVar.u(), uVar.w1(), (FolderLogger) uVar.J1.get());
            case 36:
                return new com.quizlet.features.emailconfirmation.viewmodel.f((com.quizlet.quizletandroid.interactor.t) uVar.Y0.get(), zVar.z0(), zVar.s0(), new com.quizlet.features.emailconfirmation.logging.a((EventLogger) zVar.b.l0.get(), 0));
            case 37:
                m0 m0Var = zVar.a;
                com.quizlet.data.repository.login.a aVarA0 = zVar.a0();
                com.quizlet.shared.usecase.studynotes.r rVar = (com.quizlet.shared.usecase.studynotes.r) com.quizlet.shared.usecase.di.f.c.getValue();
                S6.c(rVar);
                return new com.quizlet.features.notes.detail.viewmodels.c(m0Var, aVarA0, new com.google.firebase.messaging.p(rVar), zVar.x0());
            case 38:
                return new com.quizlet.explanations.textbook.exercisedetail.viewmodel.c(uVar.S(), zVar.B(), uVar.m0(), zVar.H0(), new com.quizlet.data.repository.folderset.c(uVar.x0(), u.v(), uVar.l0()), new com.google.firebase.messaging.p(new com.quizlet.shared.usecase.folderstudymaterials.c(25), 17), (FolderLogger) uVar.J1.get());
            case 39:
                return new com.quizlet.explanations.landingpage.viewmodel.a(zVar.B());
            case RequestError.NETWORK_FAILURE /* 40 */:
                return new com.quizlet.explanations.feedback.viewmodel.a(zVar.F0(), zVar.B());
            case RequestError.NO_DEV_KEY /* 41 */:
                return new com.quizlet.explanations.solution.viewmodel.b(zVar.B());
            case 42:
                return new com.quizlet.features.questiontypes.fitb.m(zVar.a, (com.quizlet.quizletandroid.ui.studymodes.grader.b) c4624g.n.get(), (com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a) c4624g.o.get(), uVar.j1(), z.C());
            case 43:
                return new com.quizlet.features.flashcards.settings.j(zVar.a, uVar.j1(), zVar.F(), new com.quizlet.login.authentication.login.a(14), new com.quizlet.data.interactor.achievements.f(zVar.b.W()), new com.google.firebase.crashlytics.internal.settings.b(zVar.b.W()), (com.quizlet.features.infra.basestudy.manager.a) c4624g.j.get());
            case 44:
                m0 m0Var2 = zVar.a;
                com.quizlet.features.infra.basestudy.manager.a aVar = (com.quizlet.features.infra.basestudy.manager.a) c4624g.j.get();
                com.quizlet.features.flashcards.engine.h hVarD = zVar.D();
                com.quizlet.quizletandroid.managers.audio.h hVar = (com.quizlet.quizletandroid.managers.audio.h) uVar.f0.get();
                androidx.work.impl.model.v vVarE = zVar.E();
                com.quizlet.features.infra.basestudy.usecase.b bVarS = zVar.S();
                com.quizlet.data.interactor.metering.b bVarV = zVar.V();
                u uVar5 = zVar.b;
                return new S(m0Var2, aVar, hVarD, hVar, vVarE, bVarS, new com.quizlet.data.interactor.set.c(bVarV, (com.quizlet.infra.legacysyncengine.managers.d) uVar5.Z.get(), uVar5.m0()), new com.quizlet.features.flashcards.logging.a((EventLogger) zVar.b.l0.get()), uVar.m0(), zVar.g());
            case 45:
                m0 m0Var3 = zVar.a;
                V vK = zVar.K();
                com.quizlet.features.folders.viewmodel.usecases.k kVarR = zVar.R();
                com.quizlet.data.interactor.folderwithcreator.m mVarT0 = zVar.t0();
                u uVar6 = zVar.b;
                C1608n c1608n2 = new C1608n(uVar6.l0(), uVar6.m0(), zVar.c.b(), uVar6.p1(), uVar6.w1());
                com.onetrust.otpublishers.headless.UI.fragment.q qVar = new com.onetrust.otpublishers.headless.UI.fragment.q(new com.quizlet.data.interactor.folderstudymaterial.z(new com.google.firebase.crashlytics.internal.settings.b(new com.onetrust.otpublishers.headless.UI.fragment.q(new com.quizlet.data.repository.qclass.c(uVar.K(), new com.quizlet.quizletandroid.ui.login.di.a(2)))), new com.quizlet.data.interactor.achievements.f(new com.google.firebase.messaging.p(new com.quizlet.data.repository.qclass.c(uVar.K(), new com.quizlet.quizletandroid.ui.login.di.a(2)))), new com.google.firebase.perf.logging.b(24)));
                com.google.firebase.crashlytics.internal.common.j jVarC0 = zVar.C0();
                u uVar7 = zVar.b;
                return new N(m0Var3, vK, kVarR, mVarT0, c1608n2, qVar, jVarC0, new com.quizlet.features.folders.logging.e((EventLogger) uVar7.l0.get(), new StudyFunnelEventLogger((EventLogger) uVar7.l0.get()), (com.quizlet.infra.contracts.studyfunnel.a) uVar7.D1.get()), zVar.Q(), zVar.i(), new com.quizlet.data.interactor.folder.f(uVar.G(), 0), zVar.o(), zVar.c0(), uVar.w1(), zVar.J0(), uVar.I(), uVar.J(), (FolderLogger) uVar.J1.get());
            case 46:
                return new com.quizlet.features.blocks.g(zVar.a, (com.quizlet.data.token.a) uVar.u.get(), com.quizlet.featuregate.injection.a.a());
            case 47:
                return new com.quizlet.quizletandroid.ui.globalnav.viewmodel.e((com.quizlet.quizletandroid.interactor.t) uVar.Y0.get(), zVar.n(), new com.quizlet.quizletandroid.ui.globalnav.logging.a((EventLogger) c4624g.b.l0.get()), uVar.b0());
            case 48:
                com.quizlet.login.common.interactors.d dVarT = uVar.t();
                com.quizlet.infra.legacysyncengine.managers.d dVar = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
                androidx.work.impl.model.c cVarM02 = uVar.m0();
                com.quizlet.featuregate.features.home.a aVarH = com.quizlet.featuregate.injection.a.h();
                com.quizlet.data.repository.classfolder.e eVarV0 = uVar.v0();
                com.quizlet.data.interactor.course.a aVar2 = new com.quizlet.data.interactor.course.a((EventLogger) zVar.b.l0.get());
                EventLogger eventLogger2 = (EventLogger) c4624g.b.l0.get();
                Intrinsics.checkNotNullParameter(eventLogger2, "eventLogger");
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.c cVar = new com.quizlet.quizletandroid.ui.startpage.nav2.logging.c(eventLogger2);
                EventLogger eventLogger3 = (EventLogger) c4624g.b.l0.get();
                Intrinsics.checkNotNullParameter(eventLogger3, "eventLogger");
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.a aVar3 = new com.quizlet.quizletandroid.ui.startpage.nav2.logging.a(eventLogger3);
                com.quizlet.data.interactor.achievements.f fVar = new com.quizlet.data.interactor.achievements.f((EventLogger) uVar.l0.get());
                RevisionCenterLogger revisionCenterLogger = new RevisionCenterLogger((EventLogger) c4624g.b.l0.get());
                com.quizlet.data.repository.folderwithcreatorinclass.e eVarP0 = uVar.P0();
                QIncentivesEventLogger qIncentivesEventLogger = new QIncentivesEventLogger((EventLogger) uVar.l0.get());
                AbstractC5040y abstractC5040yD = com.quizlet.featuregate.injection.a.d();
                u uVar8 = zVar.b;
                C4633r factory = (C4633r) uVar8.R1.get();
                Intrinsics.checkNotNullParameter(factory, "factory");
                return new L(dVarT, dVar, cVarM02, aVarH, eVarV0, aVar2, cVar, aVar3, fVar, revisionCenterLogger, eVarP0, qIncentivesEventLogger, new J(abstractC5040yD, factory.a("onboarding_ell_android", com.quizlet.featuregate.contracts.enums.c.a), uVar8.G0(), uVar8.j()), zVar.I0());
            case 49:
                return new com.quizlet.features.home.viewmodel.c(zVar.e0(), zVar.P(), zVar.j0(), uVar.c0());
            case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                return new com.quizlet.login.intro.viewmodel.e(uVar.h1(), new com.quizlet.analytics.marketing.appsflyer.b(uVar.q(), uVar.P0()), dagger.internal.a.a(uVar.S1), (com.quizlet.login.common.util.b) uVar.Z0.get(), zVar.n(), zVar.r0(), new com.quizlet.data.interactor.progress.c(zVar.q0(), new com.quizlet.qutils.string.c(), zVar.i0(), com.quizlet.featuregate.injection.a.d()), dagger.internal.a.a(zVar.b0), zVar.a);
            case 51:
                return new com.quizlet.login.common.interactors.o(zVar.q0(), new com.quizlet.qutils.string.c(), zVar.i0(), com.quizlet.featuregate.injection.a.d());
            case 52:
                return new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d(zVar.a, zVar.k0(), (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get(), c4624g.j(), zVar.h());
            case 53:
                return new C4556c(zVar.a, zVar.l0(), uVar.m0(), zVar.o0());
            case 54:
                return new com.quizlet.learn.viewmodel.i(zVar.a, zVar.n0(), zVar.m0());
            case 55:
                return new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i(zVar.a, zVar.k0(), (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get(), zVar.l0(), c4624g.k(), (com.quizlet.quizletandroid.managers.audio.h) uVar.f0.get(), uVar.i1());
            case 56:
                m0 m0Var4 = zVar.a;
                com.quizlet.features.infra.basestudy.manager.a aVar4 = (com.quizlet.features.infra.basestudy.manager.a) c4624g.j.get();
                com.quizlet.infra.legacysyncengine.features.properties.d dVarC = c4624g.c();
                AbstractC5040y abstractC5040yD2 = com.quizlet.featuregate.injection.a.d();
                uVar.getClass();
                com.onetrust.otpublishers.headless.UI.fragment.q qVarY0 = u.y0();
                androidx.work.impl.model.c cVarM03 = uVar.m0();
                com.quizlet.data.repository.course.membership.c cVarB0 = zVar.B0();
                com.quizlet.featuregate.features.flexiblegrading.a aVar5 = new com.quizlet.featuregate.features.flexiblegrading.a(2);
                u uVar9 = zVar.b;
                return new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.g(m0Var4, aVar4, dVarC, abstractC5040yD2, qVarY0, cVarM03, cVarB0, new com.quizlet.learn.usecase.b(aVar5, uVar9.m0(), zVar.V(), uVar9.j()));
            case 57:
                com.quizlet.features.infra.basestudy.manager.a aVar6 = (com.quizlet.features.infra.basestudy.manager.a) c4624g.j.get();
                StudyModeEventLogger.Factory factoryJ = c4624g.j();
                m0 m0Var5 = zVar.a;
                com.quizlet.quizletandroid.managers.upgrade.a aVar7 = new com.quizlet.quizletandroid.managers.upgrade.a(1);
                com.google.android.gms.internal.mlkit_common.u uVar10 = new com.google.android.gms.internal.mlkit_common.u(false);
                u uVar11 = zVar.b;
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.d dVar2 = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.d(aVar7, uVar10, (com.quizlet.infra.legacysyncengine.net.f) uVar11.U.get());
                androidx.work.impl.model.l lVarA0 = zVar.A0();
                com.quizlet.learn.logging.a aVarL0 = zVar.l0();
                com.quizlet.quizletandroid.ui.setcreation.managers.n nVarU = zVar.U();
                com.quizlet.login.common.interactors.d dVarM0 = zVar.M0();
                com.quizlet.login.authentication.login.a aVarT = zVar.T();
                com.quizlet.data.interactor.achievements.f fVar2 = new com.quizlet.data.interactor.achievements.f(uVar11.W());
                com.google.firebase.crashlytics.internal.settings.b bVar = new com.google.firebase.crashlytics.internal.settings.b(uVar11.W());
                com.quizlet.features.setpage.logging.writetransition.a aVarP0 = zVar.P0();
                com.quizlet.infra.contracts.growthbook.a aVar8 = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
                return new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i(aVar6, factoryJ, m0Var5, dVar2, lVarA0, aVarL0, nVarU, dVarM0, aVarT, fVar2, bVar, aVarP0, AbstractC4178x.i(aVar8, "growthBook", "improve_smart_grading_mobile", aVar8), com.quizlet.featuregate.injection.a.d(), c4624g.c(), new com.quizlet.learn.usecase.d(new com.quizlet.learn.usecase.b(new com.quizlet.featuregate.features.flexiblegrading.a(2), uVar11.m0(), zVar.V(), uVar11.j()), new assistantMode.utils.studiableMetadata.b(28)));
            case 58:
                m0 m0Var6 = zVar.a;
                com.quizlet.features.infra.basestudy.manager.a aVar9 = (com.quizlet.features.infra.basestudy.manager.a) c4624g.j.get();
                com.quizlet.infra.legacysyncengine.net.f fVar3 = (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get();
                com.quizlet.data.repository.progress.b bVarI = c4624g.i();
                u uVar12 = zVar.b;
                com.quizlet.features.infra.basestudy.data.models.onboarding.a aVar10 = new com.quizlet.features.infra.basestudy.data.models.onboarding.a(uVar12.q());
                com.quizlet.learn.checkpoint.a aVarF = c4624g.f();
                UserInfoCache userInfoCacheL0 = uVar.l0();
                com.quizlet.featuregate.features.studymodes.learn.a aVarG = com.quizlet.featuregate.injection.a.g();
                com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a aVar11 = (com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a) c4624g.o.get();
                io.reactivex.rxjava3.core.o oVarK = com.quizlet.featuregate.injection.a.k();
                io.reactivex.rxjava3.core.o oVarJ = com.quizlet.featuregate.injection.a.j();
                com.quizlet.infra.legacysyncengine.managers.d dVar3 = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
                com.quizlet.infra.legacysyncengine.managers.i iVar = (com.quizlet.infra.legacysyncengine.managers.i) uVar.S.get();
                com.quizlet.infra.legacysyncengine.net.c cVar2 = (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get();
                androidx.work.impl.model.c cVarM04 = uVar.m0();
                com.quizlet.data.interactor.progress.c cVarY = zVar.Y();
                com.quizlet.learn.logging.a aVarL02 = zVar.l0();
                EventLogger eventLogger4 = (EventLogger) uVar.l0.get();
                com.quizlet.infra.legacysyncengine.features.properties.d dVarC2 = c4624g.c();
                com.quizlet.data.interactor.school.b bVar2 = new com.quizlet.data.interactor.school.b(uVar12.w0(), new com.lyft.android.scissors.b(uVar12.x1()));
                com.quizlet.data.interactor.set.c cVar3 = new com.quizlet.data.interactor.set.c(zVar.V(), (com.quizlet.infra.legacysyncengine.managers.d) uVar12.Z.get(), uVar12.m0());
                w wVar = (w) zVar.j0.get();
                StudyModeMeteringEventLogger studyModeMeteringEventLoggerK = c4624g.k();
                androidx.compose.foundation.text.input.internal.u uVar13 = new androidx.compose.foundation.text.input.internal.u(uVar12.b(), uVar12.l0());
                com.quizlet.data.repository.searchexplanations.c cVar4 = new com.quizlet.data.repository.searchexplanations.c(zVar.Z(), com.quizlet.featuregate.injection.a.d());
                com.quizlet.data.connectivity.a aVar12 = (com.quizlet.data.connectivity.a) uVar.X.get();
                com.google.android.gms.internal.mlkit_common.u uVar14 = new com.google.android.gms.internal.mlkit_common.u(28);
                com.quizlet.data.repository.user.a aVarQ0 = uVar.q0();
                androidx.work.impl.model.l lVarK = zVar.k();
                com.quizlet.data.repository.user.a aVarR0 = uVar.r0();
                com.quizlet.infra.contracts.growthbook.a aVar13 = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
                return new com.quizlet.learn.viewmodel.G(m0Var6, aVar9, fVar3, bVarI, aVar10, aVarF, userInfoCacheL0, aVarG, aVar11, oVarK, oVarJ, dVar3, iVar, cVar2, cVarM04, cVarY, aVarL02, eventLogger4, dVarC2, bVar2, cVar3, wVar, studyModeMeteringEventLoggerK, uVar13, cVar4, aVar12, uVar14, aVarQ0, lVarK, aVarR0, AbstractC4178x.i(aVar13, "growthBook", "improve_smart_grading_mobile", aVar13), new com.quizlet.learn.usecase.d(new com.quizlet.learn.usecase.b(new com.quizlet.featuregate.features.flexiblegrading.a(2), uVar12.m0(), zVar.V(), uVar12.j()), new assistantMode.utils.studiableMetadata.b(28)), new com.quizlet.data.interactor.achievements.f(uVar12.W()), new com.google.firebase.crashlytics.internal.settings.b(uVar12.W()));
            case 59:
                return new w(this);
            case 60:
                zVar.getClass();
                com.quizlet.shared.usecase.studynotes.t tVar = (com.quizlet.shared.usecase.studynotes.t) com.quizlet.shared.usecase.di.f.d.getValue();
                S6.c(tVar);
                return new com.quizlet.library.viewmodels.d(new com.quizlet.data.interactor.notes.f(tVar, zVar.f0()), uVar.P(), uVar.j());
            case 61:
                return new com.quizlet.library.viewmodels.l(zVar.X(), uVar.J0());
            case 62:
                return new com.quizlet.library.viewmodels.s(new com.quizlet.data.repository.explanations.myexplanations.a(uVar.x0(), u.v()));
            case 63:
                m0 m0Var7 = zVar.a;
                long j = uVar.j();
                com.quizlet.data.interactor.folderwithcreator.m mVarU = uVar.U();
                J jI = zVar.I();
                u uVar15 = c4624g.b;
                com.quizlet.quizletandroid.interactor.m mVar = new com.quizlet.quizletandroid.interactor.m(uVar15.j(), (com.quizlet.infra.legacysyncengine.net.c) uVar15.Q.get(), new assistantMode.utils.studiableMetadata.b(29), com.quizlet.featuregate.injection.a.d());
                com.onetrust.otpublishers.headless.UI.fragment.q qVarL = zVar.L();
                androidx.work.impl.model.c cVarM05 = uVar.m0();
                com.quizlet.offline.managers.b bVar3 = (com.quizlet.offline.managers.b) uVar.d1.get();
                com.quizlet.library.logging.b bVarP0 = zVar.p0();
                com.google.firebase.crashlytics.internal.settings.b bVarB2 = c4624g.b();
                com.quizlet.quizletandroid.interactor.p pVarX = uVar.X();
                com.google.firebase.crashlytics.internal.common.j jVarB1 = uVar.b1();
                androidx.work.impl.model.c userProperties = uVar.m0();
                Intrinsics.checkNotNullParameter(userProperties, "userProperties");
                return new c0(m0Var7, j, mVarU, jI, mVar, qVarL, cVarM05, bVar3, bVarP0, bVarB2, pVarX, jVarB1, new com.quizlet.featuregate.features.folder.e(userProperties, 0), (FolderLogger) uVar.J1.get(), uVar.J0(), new androidx.work.impl.model.v(uVar.K0(), (com.quizlet.data.connectivity.a) uVar.X.get()), uVar.s0(), (com.quizlet.features.infra.basestudy.manager.d) uVar.D1.get());
            case 64:
                long j2 = uVar.j();
                com.quizlet.infra.legacysyncengine.net.c loader = (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get();
                Intrinsics.checkNotNullParameter(loader, "loader");
                return new com.quizlet.quizletandroid.ui.setpage.addset.f(new com.quizlet.features.infra.studysetting.datasource.a(loader, j2, 4));
            case 65:
                com.features.flashcards.creatormarketing.h hVarH1 = uVar.h1();
                com.google.android.gms.internal.appset.e eVarR0 = zVar.r0();
                C1721Kc c1721Kc = new C1721Kc(zVar.q0(), new com.quizlet.qutils.string.c(), zVar.i0(), com.quizlet.featuregate.injection.a.d());
                com.quizlet.data.interactor.progress.c cVar5 = new com.quizlet.data.interactor.progress.c(zVar.q0(), new com.quizlet.qutils.string.c(), zVar.i0(), com.quizlet.featuregate.injection.a.d());
                com.google.firebase.messaging.u uVar16 = new com.google.firebase.messaging.u(zVar.q0(), new com.quizlet.qutils.string.c(), zVar.i0(), com.quizlet.featuregate.injection.a.d());
                com.quizlet.infra.contracts.growthbook.a aVar14 = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
                return new com.quizlet.login.login.viewmodel.f(hVarH1, eVarR0, c1721Kc, cVar5, uVar16, AbstractC4178x.i(aVar14, "growthBook", "facebook_sso_android", aVar14));
            case 66:
                com.lyft.android.scissors.b bVar4 = new com.lyft.android.scissors.b(new C4567d((InterfaceC1076h) zVar.b.C1.get(), 0));
                u uVar17 = zVar.b;
                return new com.quizlet.features.emailconfirmation.viewmodel.m(bVar4, new com.google.mlkit.vision.documentscanner.internal.c(new C4567d((InterfaceC1076h) uVar17.C1.get(), 0)), new com.quizlet.data.interactor.course.a(new com.quizlet.remote.model.login.magiclink.b(uVar17.n0(), com.quizlet.featuregate.injection.a.d())), new com.quizlet.features.emailconfirmation.logging.a((EventLogger) uVar17.l0.get(), 0));
            case 67:
                return new com.quizlet.login.magiclink.viewmodel.g((com.quizlet.usecase.a) uVar.o.get(), zVar.s0());
            case 68:
                return new com.quizlet.login.magiclink.viewmodel.j(new com.quizlet.data.interactor.course.a(new com.quizlet.remote.model.login.magiclink.b(zVar.b.n0(), com.quizlet.featuregate.injection.a.d())));
            case 69:
                m0 m0Var8 = zVar.a;
                com.quizlet.features.notes.logging.f fVarX0 = zVar.x0();
                long j3 = uVar.j();
                com.quizlet.data.interactor.metering.b bVarV2 = zVar.V();
                com.quizlet.data.repository.login.a aVarA02 = zVar.a0();
                com.google.firebase.crashlytics.internal.settings.b bVarB3 = c4624g.b();
                com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G g = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G) c4624g.s.get();
                com.quizlet.shared.usecase.studynotes.r rVar2 = (com.quizlet.shared.usecase.studynotes.r) com.quizlet.shared.usecase.di.f.c.getValue();
                S6.c(rVar2);
                com.google.firebase.messaging.p pVar = new com.google.firebase.messaging.p(rVar2);
                u uVar18 = zVar.b;
                return new com.quizlet.features.notes.detail.viewmodels.v(m0Var8, fVarX0, j3, bVarV2, aVarA02, bVarB3, g, pVar, new androidx.work.impl.model.c(uVar18.l0(), (com.quizlet.utmhelper.c) zVar.D.get()), new com.quizlet.data.interactor.achievements.f(uVar18.E0()), new com.lyft.android.scissors.b(uVar18.E0()), new com.google.android.material.floatingactionbutton.c(uVar18.E0()), new com.google.firebase.crashlytics.internal.common.j((com.quizlet.cache.a) uVar18.O1.get()), (FolderLogger) uVar.J1.get());
            case 70:
                return new com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a(zVar.a, (com.quizlet.features.infra.basestudy.manager.a) c4624g.j.get(), c4624g.h(), zVar.u0(), zVar.v0(), zVar.w0(), (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get(), uVar.m0(), new com.quizlet.features.match.highscore.b(zVar.b.q()));
            case 71:
                return new com.quizlet.features.match.viewmodel.f(zVar.a, (com.quizlet.features.match.studyengine.f) c4624g.k.get(), zVar.w0());
            case 72:
                return new com.quizlet.features.match.viewmodel.h(zVar.a, c4624g.h());
            case 73:
                m0 m0Var9 = zVar.a;
                com.quizlet.features.infra.basestudy.manager.a aVar15 = (com.quizlet.features.infra.basestudy.manager.a) c4624g.j.get();
                androidx.compose.foundation.text.input.internal.u uVarH = c4624g.h();
                com.quizlet.data.repository.studysetwithcreator.d dVarV0 = zVar.v0();
                com.quizlet.data.repository.course.membership.c cVarW0 = zVar.w0();
                androidx.work.impl.model.c cVarM06 = uVar.m0();
                u uVar19 = zVar.b;
                Context context = uVar19.q();
                Intrinsics.checkNotNullParameter(context, "context");
                SharedPreferences sharedPreferences = context.getSharedPreferences("MATCH_MUSIC_SHARED_PREF", 0);
                Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
                S6.c(sharedPreferences);
                return new com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g(m0Var9, aVar15, uVarH, dVarV0, cVarW0, cVarM06, new C1544a(sharedPreferences), (com.quizlet.quizletandroid.audio.players.c) uVar.Z1.get(), new com.quizlet.features.match.audio.a(uVar19.q()), uVar.y());
            case 74:
                return new com.quizlet.quizletandroid.ui.login.accountrecovery.loginduplicate.d();
            case 75:
                return new com.quizlet.features.questiontypes.mcq.l(zVar.a, new com.quizlet.data.repository.studysetwithcreator.d(new com.quizlet.features.questiontypes.basequestion.c()), (com.quizlet.quizletandroid.ui.studymodes.grader.b) c4624g.n.get(), (QuestionEventLogger) c4624g.h.get(), (com.quizlet.quizletandroid.managers.audio.h) uVar.f0.get(), (com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a) c4624g.o.get(), new com.google.mlkit.common.sdkinternal.b(24));
            case 76:
                com.quizlet.quizletandroid.ui.profile.data.b repository = new com.quizlet.quizletandroid.ui.profile.data.b(1);
                zVar.b.getClass();
                androidx.work.impl.model.c dispatcher = u.v();
                Intrinsics.checkNotNullParameter(repository, "repository");
                Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
                com.google.android.material.shape.e getFeaturedExplanationsUseCase = new com.google.android.material.shape.e(24);
                androidx.work.impl.model.c userProperties2 = uVar.m0();
                Intrinsics.checkNotNullParameter(getFeaturedExplanationsUseCase, "getFeaturedExplanationsUseCase");
                Intrinsics.checkNotNullParameter(userProperties2, "userProperties");
                com.quizlet.explanations.myexplanations.viewmodel.b bVar5 = new com.quizlet.explanations.myexplanations.viewmodel.b();
                new Y();
                return bVar5;
            case AndroidTcfDataLoader.COMSCORE_VENDOR_INDEX /* 77 */:
                return new com.quizlet.explanations.myexplanations.viewmodel.m(zVar.a, new com.quizlet.data.repository.explanations.myexplanations.a(uVar.x0(), u.v()), zVar.B(), uVar.m0());
            case 78:
                com.quizlet.data.repository.searchexplanations.c cVar6 = new com.quizlet.data.repository.searchexplanations.c(new com.google.android.gms.internal.appset.e(zVar.b.k0(), new com.quizlet.remote.model.explanations.search.c(), com.quizlet.featuregate.injection.a.d()), (com.quizlet.cache.a) zVar.D0.get());
                u uVar20 = zVar.b;
                return new com.quizlet.search.viewmodels.p(cVar6, new com.quizlet.search.logging.b((EventLogger) uVar20.l0.get()), zVar.B(), uVar.p0(), (SearchEventLogger) uVar.G1.get(), new com.google.firebase.messaging.p(new com.quizlet.remote.model.search.d(uVar20.k0(), new com.quizlet.quizletandroid.ui.common.images.capture.b(3), com.quizlet.featuregate.injection.a.d())), uVar.j(), new com.quizlet.search.logging.a((EventLogger) uVar20.l0.get()));
            case 79:
                return new com.quizlet.local.cache.a(1);
            case 80:
                return new com.quizlet.features.infra.folder.tag.viewmodel.d(new com.quizlet.data.interactor.course.a(uVar.G()), new com.quizlet.data.interactor.school.b(uVar.G()), uVar.w1(), (FolderLogger) uVar.J1.get());
            case 81:
                return new com.quizlet.login.recovery.forgotpassword.viewmodel.e((IQuizletApiClient) uVar.O.get(), com.quizlet.featuregate.injection.a.l(), com.quizlet.featuregate.injection.a.j());
            case 82:
                m0 m0Var10 = zVar.a;
                io.ktor.client.plugins.api.d dVarT0 = uVar.t0();
                io.reactivex.rxjava3.core.o oVarL = com.quizlet.featuregate.injection.a.l();
                io.reactivex.rxjava3.core.o oVarJ2 = com.quizlet.featuregate.injection.a.j();
                com.google.android.gms.internal.appset.e eVarR02 = zVar.r0();
                io.ktor.client.plugins.api.d dVarQ0 = zVar.q0();
                androidx.work.impl.model.l lVarF1 = uVar.f1();
                com.quizlet.login.common.util.b bVar6 = (com.quizlet.login.common.util.b) uVar.Z0.get();
                com.quizlet.login.common.interactors.d dVarT2 = uVar.t();
                u uVar21 = zVar.b;
                return new com.quizlet.login.oldlogin.o(m0Var10, dVarT0, oVarL, oVarJ2, eVarR02, dVarQ0, lVarF1, bVar6, dVarT2, new com.quizlet.data.interactor.achievements.f((com.quizlet.billing.subscriptions.i) uVar21.u0.get()), uVar.a1(), new com.google.mlkit.vision.documentscanner.internal.c(new C4567d((InterfaceC1076h) uVar21.C1.get(), 0)), uVar.P0(), zVar.y0(), new com.google.firebase.crashlytics.internal.common.j(uVar21.G0()));
            case 83:
                return new com.quizlet.quizletandroid.ui.login.viewmodels.f(new androidx.work.impl.model.v(zVar.b.g1(), u.v()), com.quizlet.featuregate.injection.a.l(), com.quizlet.featuregate.injection.a.j());
            case 84:
                zVar.getClass();
                AbstractC5040y abstractC5040yD3 = com.quizlet.featuregate.injection.a.d();
                u uVar22 = zVar.b;
                C4633r factory2 = (C4633r) uVar22.R1.get();
                Intrinsics.checkNotNullParameter(factory2, "factory");
                return new com.quizlet.features.onboarding.ell.B(new J(abstractC5040yD3, factory2.a("onboarding_ell_android", com.quizlet.featuregate.contracts.enums.c.a), uVar22.G0(), uVar22.j()), new com.quizlet.features.onboarding.ell.n((EventLogger) uVar22.l0.get()));
            case 85:
                return new com.quizlet.features.onboarding.flashcards.n(uVar.j(), new com.quizlet.features.onboarding.flashcards.j((EventLogger) zVar.b.l0.get()), uVar.H0());
            case 86:
                m0 m0Var11 = zVar.a;
                u uVar23 = zVar.b;
                androidx.work.impl.model.c cVarM07 = uVar23.m0();
                AbstractC5040y abstractC5040yD4 = com.quizlet.featuregate.injection.a.d();
                com.quizlet.infra.contracts.growthbook.a aVar16 = (com.quizlet.infra.contracts.growthbook.a) uVar23.y0.get();
                com.quizlet.features.onboarding.survey.j jVar = new com.quizlet.features.onboarding.survey.j(abstractC5040yD4, AbstractC4178x.i(aVar16, "growthBook", "onboarding_survey_android", aVar16), uVar23.I0());
                AbstractC5040y abstractC5040yD5 = com.quizlet.featuregate.injection.a.d();
                com.quizlet.infra.contracts.growthbook.a aVar17 = (com.quizlet.infra.contracts.growthbook.a) uVar23.y0.get();
                return new com.quizlet.features.onboarding.navigation.p(m0Var11, new com.quizlet.data.repository.progress.b(cVarM07, jVar, new androidx.work.impl.model.e(abstractC5040yD5, AbstractC4178x.i(aVar17, "growthBook", "onboarding_flashcards_android", aVar17), uVar23.H0()), zVar.y0()));
            case 87:
                return new com.quizlet.features.onboarding.survey.q(uVar.j(), uVar.I0(), new com.quizlet.features.onboarding.survey.k((EventLogger) zVar.b.l0.get()));
            case 88:
                m0 m0Var12 = zVar.a;
                io.ktor.client.plugins.api.d dVarQ02 = zVar.q0();
                com.google.android.gms.internal.appset.e eVarR03 = zVar.r0();
                com.quizlet.qutils.string.c cVar7 = new com.quizlet.qutils.string.c();
                u uVar24 = zVar.b;
                return new com.quizlet.login.parentemail.viewmodel.e(m0Var12, new com.quizlet.data.repository.achievements.h(dVarQ02, eVarR03, cVar7, (com.quizlet.login.common.util.b) uVar24.Z0.get(), new com.quizlet.time.b(), new com.google.firebase.heartbeatinfo.e(new com.quizlet.time.b()), uVar24.f1(), zVar.i0(), com.quizlet.featuregate.injection.a.d()), new com.quizlet.login.common.interactors.d(uVar24.g1()));
            case 89:
                m0 m0Var13 = zVar.a;
                com.quizlet.features.notes.logging.f fVarX02 = zVar.x0();
                long j4 = uVar.j();
                com.quizlet.data.interactor.metering.b bVarV3 = zVar.V();
                u uVar25 = zVar.b;
                long j5 = uVar25.j();
                com.quizlet.data.repository.user.e eVarV1 = uVar25.v1();
                com.quizlet.shared.usecase.studynotes.p pVar2 = (com.quizlet.shared.usecase.studynotes.p) com.quizlet.shared.usecase.di.f.b.getValue();
                S6.c(pVar2);
                com.quizlet.data.interactor.notes.b bVar7 = new com.quizlet.data.interactor.notes.b(j5, eVarV1, pVar2);
                com.quizlet.infra.contracts.growthbook.a growthBook = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
                Intrinsics.checkNotNullParameter(growthBook, "growthBook");
                com.quizlet.data.repository.explanations.question.a aVar18 = new com.quizlet.data.repository.explanations.question.a(growthBook, "study_guide_upload_character_minimum_android", (Integer) 100);
                com.quizlet.infra.contracts.growthbook.a growthBook2 = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
                Intrinsics.checkNotNullParameter(growthBook2, "growthBook");
                com.quizlet.data.repository.explanations.question.a aVar19 = new com.quizlet.data.repository.explanations.question.a(growthBook2, "study_guide_upload_character_maximum_android", Integer.valueOf(ConnectivityType.UNKNOWN));
                com.quizlet.infra.contracts.growthbook.a growthBook3 = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
                Intrinsics.checkNotNullParameter(growthBook3, "growthBook");
                return new com.quizlet.features.notes.upload.viewmodels.e(m0Var13, fVarX02, j4, bVarV3, bVar7, aVar18, aVar19, new com.quizlet.data.repository.explanations.question.a(growthBook3, "study_guide_upload_file_size_maximum_android", (Integer) 25600), new com.google.firebase.crashlytics.internal.settings.b(new com.onetrust.otpublishers.headless.UI.fragment.q(new com.quizlet.data.repository.qclass.c(uVar.K(), new com.quizlet.quizletandroid.ui.login.di.a(2)))));
            case SubsamplingScaleImageView.ORIENTATION_90 /* 90 */:
                m0 m0Var14 = zVar.a;
                com.google.mlkit.common.sdkinternal.b bVar8 = new com.google.mlkit.common.sdkinternal.b(27);
                u uVar26 = zVar.b;
                return new com.quizlet.features.practicetest.detail.viewmodel.i(m0Var14, bVar8, new com.quizlet.data.interactor.course.a(uVar26.L0()), new com.google.firebase.perf.logging.b(27), uVar.K0(), uVar.l0(), new PracticeTestEventLogger((EventLogger) uVar26.l0.get()), new androidx.camera.camera2.internal.c0(new com.google.firebase.crashlytics.internal.settings.b(uVar26.L0()), new com.quizlet.data.repository.activitycenter.b(uVar26.L0(), uVar26.l0()), new com.google.firebase.heartbeatinfo.e(27), new com.google.mlkit.common.internal.model.a(27), zVar.c.l(), uVar26.l0()), new com.quizlet.data.repository.explanations.myexplanations.a(uVar26.L0(), uVar26.l0()), new com.quizlet.qutils.string.c());
            case 91:
                m0 m0Var15 = zVar.a;
                u uVar27 = zVar.b;
                return new com.quizlet.features.practicetest.results.viewmodel.h(m0Var15, new com.onetrust.otpublishers.headless.UI.fragment.q(uVar27.L0()), new com.quizlet.data.repository.folderwithcreator.e(new com.quizlet.features.practicetest.results.usecase.a(), new com.google.firebase.heartbeatinfo.e(27), zVar.c.l()), new com.google.mlkit.vision.documentscanner.internal.c(uVar27.L0()), new com.google.firebase.crashlytics.internal.common.j(uVar27.L0()), new com.quizlet.data.interactor.course.a(uVar27.L0()), new com.google.firebase.perf.logging.b(27), new PracticeTestEventLogger((EventLogger) uVar27.l0.get()));
            case 92:
                m0 m0Var16 = zVar.a;
                u uVar28 = zVar.b;
                return new com.quizlet.features.practicetest.takingtest.viewmodel.l(m0Var16, new com.quizlet.features.practicetest.takingtest.usecase.f(new com.quizlet.data.interactor.achievements.f(uVar28.L0()), new com.quizlet.data.interactor.course.a(uVar28.L0()), new com.google.firebase.messaging.p(uVar28.L0()), new com.google.firebase.crashlytics.internal.settings.b(uVar28.L0()), new com.google.firebase.heartbeatinfo.e(27)), uVar.K0(), new PracticeTestEventLogger((EventLogger) uVar28.l0.get()), uVar.l0(), new com.google.mlkit.vision.documentscanner.internal.c(uVar28.L0()), new com.quizlet.qutils.string.c());
            case 93:
                m0 savedStateHandle = zVar.a;
                com.quizlet.infra.legacysyncengine.net.c loader2 = (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get();
                Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
                Intrinsics.checkNotNullParameter(loader2, "loader");
                Object objA = savedStateHandle.a("user_id");
                if (objA != null) {
                    return new com.quizlet.quizletandroid.ui.profile.o(new com.quizlet.features.infra.studysetting.datasource.a(loader2, ((Number) objA).longValue(), 4));
                }
                throw new IllegalArgumentException("Required value was null.");
            case 94:
                com.quizlet.data.interactor.set.c cVarF0 = zVar.f0();
                UserInfoCache userInfoCacheL02 = uVar.l0();
                com.google.firebase.messaging.p pVarA = c4624g.a();
                com.quizlet.infra.legacysyncengine.managers.d dVar4 = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
                u uVar29 = c4624g.b;
                com.quizlet.data.interactor.course.a aVar20 = new com.quizlet.data.interactor.course.a((Braze) uVar29.W0.get());
                Context context2 = uVar29.q();
                Intrinsics.checkNotNullParameter(context2, "context");
                SharedPreferences sharedPreferences2 = context2.getSharedPreferences("BRAZE_EVENT_SHARED_PREF", 0);
                Intrinsics.checkNotNullExpressionValue(sharedPreferences2, "getSharedPreferences(...)");
                S6.c(sharedPreferences2);
                return new com.quizlet.quizletandroid.ui.profile.data.h(cVarF0, userInfoCacheL02, pVarA, dVar4, new com.quizlet.quizletandroid.braze.events.b(aVar20, new com.quizlet.db.b(sharedPreferences2, 2), uVar29.l0()), new com.quizlet.features.userprofile.a((EventLogger) zVar.b.l0.get()));
            case 95:
                return new com.quizlet.explanations.questiondetail.viewmodel.f(zVar.a, new com.quizlet.data.repository.qclass.c(new com.quizlet.data.repository.explanations.question.a(new com.google.firebase.crashlytics.internal.settings.b(new androidx.work.impl.model.l(uVar.A(), new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(new com.quizlet.quizletandroid.ui.profile.p(1), new com.quizlet.quizletandroid.ui.common.images.capture.a(new com.quizlet.quizletandroid.ui.profile.p(1))), new com.quizlet.quizletandroid.logging.initializer.a(2))), (com.quizlet.data.connectivity.a) uVar.X.get(), AbstractC4178x.o((org.slf4j.a) uVar.Y.get(), "loggerFactory", com.quizlet.data.repository.explanations.question.a.class, "getLogger(...)")), u.v()), new com.quizlet.data.repository.searchexplanations.c(new com.quizlet.remote.model.explanations.question.recommendations.b(zVar.b.A(), new k(u.Y0())), com.quizlet.featuregate.injection.a.d()), new com.quizlet.data.repository.folderset.c(uVar.x0(), u.v(), uVar.l0()), zVar.B(), uVar.l0(), uVar.m0(), zVar.H0(), new com.google.firebase.messaging.p(new com.quizlet.shared.usecase.folderstudymaterials.c(25), 17), (FolderLogger) uVar.J1.get());
            case 96:
                return new com.quizlet.features.questiontypes.basequestion.k(zVar.a, (com.quizlet.quizletandroid.ui.studymodes.grader.b) c4624g.n.get(), (com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a) c4624g.o.get());
            case 97:
                return new com.quizlet.features.questionnaire.navigation.m(zVar.a, new com.onetrust.otpublishers.headless.Internal.Helper.h(27), com.quizlet.featuregate.injection.a.d(), (com.quizlet.usecase.a) c4624g.e.get());
            case 98:
                return new QuizletLiveViewModel(uVar.p0(), new com.quizlet.infra.legacysyncengine.managers.g(uVar.q()), (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get());
            case 99:
                return new com.quizlet.features.settings.viewmodels.u(zVar.O0());
            default:
                throw new AssertionError(i);
        }
    }

    /* JADX WARN: Type inference failed for: r16v11, types: [java.lang.Object, kotlin.k] */
    @Override // javax.inject.a
    public final Object get() {
        int i = this.d;
        int i2 = i / 100;
        if (i2 == 0) {
            return a();
        }
        if (i2 != 1) {
            throw new AssertionError(i);
        }
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        C4624g c4624g = this.b;
        z zVar = this.c;
        u uVar = this.a;
        switch (i) {
            case 100:
                m0 m0Var = zVar.a;
                retrofit2.L l = (retrofit2.L) zVar.b.a1.get();
                Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.w.class);
                Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
                com.quizlet.remote.service.w wVar = (com.quizlet.remote.service.w) objL;
                S6.c(wVar);
                return new com.quizlet.report.viewmodels.c(m0Var, new com.quizlet.data.interactor.course.a(new com.quizlet.remote.model.report.c(wVar, com.quizlet.featuregate.injection.a.d())));
            case 101:
                return new com.quizlet.login.resetpassword.viewmodel.c(new androidx.work.impl.model.e((IQuizletApiClient) zVar.b.O.get(), com.quizlet.featuregate.injection.a.d()));
            case 102:
                u uVar2 = zVar.b;
                return new com.quizlet.features.infra.folder.save.viewmodel.c(new l1(uVar2.L(), uVar2.j()), (FolderLogger) uVar.J1.get());
            case 103:
                com.quizlet.infra.legacysyncengine.net.c loader = (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get();
                com.quizlet.infra.legacysyncengine.net.f syncDispatcher = (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get();
                ExecutionRouter executionRouter = (ExecutionRouter) uVar.w.get();
                DatabaseHelper databaseHelper = (DatabaseHelper) uVar.v.get();
                com.quizlet.infra.legacysyncengine.managers.i uiModelSaveManager = (com.quizlet.infra.legacysyncengine.managers.i) uVar.S.get();
                com.quizlet.quizletandroid.ui.setcreation.managers.interfaces.a studySetChangeState = (com.quizlet.quizletandroid.ui.setcreation.managers.interfaces.a) uVar.F1.get();
                com.quizlet.quizletandroid.ui.setcreation.managers.p studySetLastEditTracker = uVar.k1();
                Intrinsics.checkNotNullParameter(loader, "loader");
                Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
                Intrinsics.checkNotNullParameter(executionRouter, "executionRouter");
                Intrinsics.checkNotNullParameter(databaseHelper, "databaseHelper");
                Intrinsics.checkNotNullParameter(uiModelSaveManager, "uiModelSaveManager");
                Intrinsics.checkNotNullParameter(studySetChangeState, "studySetChangeState");
                Intrinsics.checkNotNullParameter(studySetLastEditTracker, "studySetLastEditTracker");
                Zh zh = new Zh(loader, syncDispatcher, executionRouter, databaseHelper, uiModelSaveManager, studySetChangeState, studySetLastEditTracker);
                Context context = uVar.q();
                IQuizletApiClient quizletApi = (IQuizletApiClient) uVar.O.get();
                io.reactivex.rxjava3.core.o mainThreadScheduler = com.quizlet.featuregate.injection.a.j();
                io.reactivex.rxjava3.core.o networkScheduler = com.quizlet.featuregate.injection.a.l();
                io.reactivex.rxjava3.core.o ioScheduler = io.reactivex.rxjava3.schedulers.e.c;
                Intrinsics.checkNotNullExpressionValue(ioScheduler, "io(...)");
                S6.c(ioScheduler);
                Intrinsics.checkNotNullParameter(context, "appContext");
                Intrinsics.checkNotNullParameter(quizletApi, "quizletApi");
                Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
                Intrinsics.checkNotNullParameter(networkScheduler, "networkScheduler");
                Intrinsics.checkNotNullParameter(ioScheduler, "ioScheduler");
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(quizletApi, "quizletApi");
                Intrinsics.checkNotNullParameter(networkScheduler, "networkScheduler");
                Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
                Intrinsics.checkNotNullParameter(ioScheduler, "ioScheduler");
                com.quizlet.data.interactor.folderwithcreator.m mVar = new com.quizlet.data.interactor.folderwithcreator.m();
                mVar.a = context;
                mVar.b = quizletApi;
                mVar.c = networkScheduler;
                mVar.d = mainThreadScheduler;
                mVar.e = ioScheduler;
                return new com.quizlet.quizletandroid.ui.setcreation.viewmodels.h(zh, mVar, (com.quizlet.scandocument.a) zVar.c1.get(), (com.quizlet.quizletandroid.ui.setcreation.tracking.c) zVar.d1.get());
            case 104:
                return new com.quizlet.scandocument.a();
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED /* 105 */:
                com.quizlet.quizletandroid.injection.modules.a aVar = uVar.h;
                EventLogger eventLogger = (EventLogger) uVar.l0.get();
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                return new com.quizlet.quizletandroid.ui.setcreation.tracking.c(eventLogger);
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF /* 106 */:
                EventLogger eventLogger2 = (EventLogger) zVar.b.l0.get();
                Intrinsics.checkNotNullParameter(eventLogger2, "eventLogger");
                return new com.quizlet.features.notes.paywall.l(new com.google.mlkit.vision.documentscanner.internal.c(eventLogger2), c4624g.l());
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED /* 107 */:
                u uVar3 = zVar.b;
                return new com.quizlet.search.viewmodels.r(new com.quizlet.data.repository.folderwithcreatorinclass.e(new com.google.firebase.crashlytics.internal.common.j(new io.ktor.client.plugins.api.d(uVar3.k0(), new com.quizlet.data.repository.user.a(new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a(3), new com.quizlet.remote.model.school.a(), new com.quizlet.quizletandroid.ui.activitycenter.models.a(), new com.quizlet.quizletandroid.ui.profile.data.b(3), new com.quizlet.quizletandroid.managers.upgrade.a(2), new k(u.Y0()), new com.quizlet.quizletandroid.ui.setcreation.adapters.a(3), new com.quizlet.quizletandroid.ui.joincontenttofolder.i(3), new com.quizlet.quizletandroid.ui.joincontenttofolder.j(3)), com.quizlet.featuregate.injection.a.d())), uVar3.m0(), new com.quizlet.remote.model.set.d(new com.quizlet.quizletandroid.ui.login.h(uVar3.k0()), new com.quizlet.search.logging.a((EventLogger) zVar.b.l0.get())), com.quizlet.featuregate.injection.a.d()), (SearchEventLogger) uVar.G1.get());
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY /* 108 */:
                u uVar4 = zVar.b;
                retrofit2.L l2 = (retrofit2.L) uVar4.W.get();
                Object objL2 = AbstractC4178x.l(l2, "retrofit", l2, "retrofit", InterfaceC4778e.class);
                Intrinsics.checkNotNullExpressionValue(objL2, "create(...)");
                InterfaceC4778e interfaceC4778e = (InterfaceC4778e) objL2;
                S6.c(interfaceC4778e);
                com.quizlet.login.common.interactors.d dataSource = new com.quizlet.login.common.interactors.d(interfaceC4778e);
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a classMapper = new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a(3);
                com.quizlet.remote.model.school.a schoolMapper = new com.quizlet.remote.model.school.a();
                com.quizlet.quizletandroid.ui.folder.logging.a pagingMapper = new com.quizlet.quizletandroid.ui.folder.logging.a(3);
                Intrinsics.checkNotNullParameter(dataSource, "dataSource");
                Intrinsics.checkNotNullParameter(classMapper, "classMapper");
                Intrinsics.checkNotNullParameter(schoolMapper, "schoolMapper");
                Intrinsics.checkNotNullParameter(pagingMapper, "pagingMapper");
                com.google.firebase.messaging.u uVar5 = new com.google.firebase.messaging.u();
                uVar5.a = dataSource;
                uVar5.b = classMapper;
                uVar5.c = schoolMapper;
                uVar5.d = pagingMapper;
                return new com.quizlet.search.viewmodels.u(new com.google.mlkit.vision.documentscanner.internal.c(new com.quizlet.data.repository.qclass.c(uVar5, (com.quizlet.data.connectivity.a) uVar4.X.get(), AbstractC4178x.o((org.slf4j.a) uVar4.Y.get(), "loggerFactory", com.quizlet.data.repository.qclass.c.class, "getLogger(...)"), com.quizlet.featuregate.injection.a.d())), zVar.E0(), new com.quizlet.quizletandroid.ui.common.images.capture.a(), (SearchEventLogger) uVar.G1.get());
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION /* 109 */:
                return new com.quizlet.search.viewmodels.x(uVar.B(), uVar.m0(), zVar.E0(), new com.quizlet.quizletandroid.ui.common.images.capture.a(), (SearchEventLogger) uVar.G1.get());
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED /* 110 */:
                return new com.quizlet.search.viewmodels.A(new com.quizlet.data.interactor.studysetwithcreator.a(zVar.b.l1(), 0), zVar.E0(), new com.quizlet.quizletandroid.ui.common.images.capture.a(), (SearchEventLogger) uVar.G1.get());
            case 111:
                return new com.quizlet.search.viewmodels.D(uVar.B(), uVar.m0(), zVar.E0(), new com.quizlet.quizletandroid.ui.common.images.capture.a(), (SearchEventLogger) uVar.G1.get());
            case ContentType.LONG_FORM_ON_DEMAND /* 112 */:
                return new com.quizlet.search.viewmodels.G(new com.quizlet.data.interactor.achievements.f(zVar.b.v1()), zVar.E0(), new com.quizlet.quizletandroid.ui.common.images.capture.a(), (SearchEventLogger) uVar.G1.get());
            case ContentType.LIVE /* 113 */:
                com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = new com.quizlet.data.repository.studysetwithcreatorinclass.g((okhttp3.n) uVar.M.get(), new com.google.mlkit.common.sdkinternal.model.a(29), new com.quizlet.local.datastore.preferences.J((InterfaceC1076h) uVar.L.get()), uVar.V());
                com.quizlet.usecase.b bVar = (com.quizlet.usecase.b) uVar.H.get();
                com.quizlet.features.emailconfirmation.logging.a aVar2 = new com.quizlet.features.emailconfirmation.logging.a((EventLogger) uVar.l0.get(), 4);
                C4184z c4184z = com.quizlet.quizletandroid.provider.a.a;
                S6.c(c4184z);
                return new com.quizlet.security.challenge.viewmodel.d(gVar, bVar, aVar2, c4184z, uVar.D0());
            case 114:
                com.google.firebase.crashlytics.internal.common.j jVar = new com.google.firebase.crashlytics.internal.common.j(new com.onetrust.otpublishers.headless.UI.fragment.q(zVar.b.W0()));
                u uVar6 = zVar.b;
                return new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o(jVar, new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i(new com.google.firebase.crashlytics.internal.settings.b(uVar6.W0()), zVar.s(), zVar.x(), zVar.D0(), uVar6.m0()), new com.google.firebase.messaging.p(new com.google.firebase.messaging.p(uVar6.U0())), new com.onetrust.otpublishers.headless.UI.fragment.q(new com.google.firebase.crashlytics.internal.settings.b(uVar6.U0())), new com.quizlet.data.repository.widget.b(new com.quizlet.data.interactor.achievements.f(uVar6.W0()), new com.quizlet.data.interactor.achievements.f(uVar6.U0())), (FolderLogger) uVar.J1.get());
            case 115:
                return new com.quizlet.features.setpage.viewmodel.selectedtermsmode.b(zVar.a, c4624g.e(), new androidx.work.impl.model.v(zVar.b.d1(), zVar.c.g()));
            case 116:
                return new com.quizlet.features.questiontypes.selfassessment.h(zVar.a, (QuestionEventLogger) c4624g.h.get(), new com.quizlet.features.infra.basestudy.data.models.onboarding.a(zVar.b.q()), (com.quizlet.quizletandroid.managers.audio.h) uVar.f0.get(), (com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a) c4624g.o.get());
            case 117:
                return new com.quizlet.quizletandroid.ui.onboarding.h(zVar.a, new com.quizlet.quizletandroid.ui.onboarding.a(0), com.quizlet.featuregate.injection.a.d());
            case 118:
                return new com.quizlet.features.setpage.header.viewmodel.f(zVar.a, zVar.b0(), new com.google.firebase.messaging.p((EventLogger) uVar.l0.get()), (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G) c4624g.s.get(), (SetPagePerformanceLogger) c4624g.i.get());
            case 119:
                return new SetPageMobileWebViewModel();
            case 120:
                m0 m0Var2 = zVar.a;
                u uVar7 = zVar.b;
                return new com.quizlet.features.setpage.progress.presentation.viewmodel.a(m0Var2, new com.quizlet.data.repository.user.a(new com.quizlet.data.interactor.school.e((com.quizlet.infra.legacysyncengine.net.c) uVar7.Q.get(), zVar.Y(), uVar7.j()), new com.quizlet.shared.usecase.folderstudymaterials.c(27), com.quizlet.featuregate.injection.a.k()), new com.features.flashcards.creatormarketing.h((EventLogger) uVar.l0.get(), 1), new com.quizlet.data.repository.set.f(uVar7.M0(), u.v(), new com.google.mlkit.vision.documentscanner.internal.c(uVar7.x1())), uVar.j(), (SetPagePerformanceLogger) c4624g.i.get());
            case ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND /* 121 */:
                m0 m0Var3 = zVar.a;
                u uVar8 = zVar.b;
                J j = new J((com.quizlet.infra.legacysyncengine.net.c) uVar8.Q.get(), uVar8.j(), zVar.b0(), new com.quizlet.shared.usecase.srs.a(new assistantMode.utils.studiableMetadata.b(29), new com.quizlet.local.ormlite.models.set.a()));
                com.quizlet.infra.legacysyncengine.datasources.factory.b bVar2 = (com.quizlet.infra.legacysyncengine.datasources.factory.b) c4624g.p.get();
                androidx.work.impl.model.c cVarM0 = uVar.m0();
                EventLogger eventLogger3 = (EventLogger) uVar.l0.get();
                com.google.firebase.messaging.p pVar = new com.google.firebase.messaging.p((EventLogger) uVar.l0.get());
                SearchEventLogger searchEventLogger = (SearchEventLogger) uVar.G1.get();
                com.quizlet.features.notes.a aVarL = uVar.l();
                Intrinsics.checkNotNullParameter((EventLogger) uVar.l0.get(), "eventLogger");
                com.quizlet.quizletandroid.ui.folder.logging.a aVar3 = new com.quizlet.quizletandroid.ui.folder.logging.a(0);
                com.features.flashcards.creatormarketing.h hVar = new com.features.flashcards.creatormarketing.h((EventLogger) uVar.l0.get(), 1);
                com.quizlet.infra.legacysyncengine.net.f fVar = (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get();
                UserInfoCache userInfoCacheL0 = uVar.l0();
                com.facebook.z zVarD1 = uVar8.d1();
                C4624g c4624g2 = zVar.c;
                androidx.work.impl.model.v vVar = new androidx.work.impl.model.v(zVarD1, c4624g2.g());
                androidx.work.impl.model.n nVarE1 = uVar.e1();
                Context context2 = uVar.q();
                Context context3 = uVar.q();
                Intrinsics.checkNotNullParameter(context3, "context");
                Object systemService = context3.getSystemService("shortcut");
                Intrinsics.e(systemService, "null cannot be cast to non-null type android.content.pm.ShortcutManager");
                ShortcutManager shortcutManager = (ShortcutManager) systemService;
                Intrinsics.checkNotNullParameter(context2, "context");
                Intrinsics.checkNotNullParameter(shortcutManager, "shortcutManager");
                androidx.work.impl.model.c cVar = new androidx.work.impl.model.c(context2, shortcutManager);
                com.quizlet.data.repository.folderwithcreatorinclass.e eVar = new com.quizlet.data.repository.folderwithcreatorinclass.e((IQuizletApiClient) uVar8.O.get(), (com.quizlet.infra.legacysyncengine.net.c) uVar8.Q.get(), (com.quizlet.infra.legacysyncengine.managers.h) uVar8.f1.get(), com.quizlet.featuregate.injection.a.j(), com.quizlet.featuregate.injection.a.l());
                com.quizlet.data.interactor.achievements.f fVar2 = new com.quizlet.data.interactor.achievements.f((com.quizlet.quizletandroid.interactor.t) uVar8.Y0.get());
                com.quizlet.data.connectivity.a aVar4 = (com.quizlet.data.connectivity.a) uVar.X.get();
                com.quizlet.features.setpage.offline.k kVar = (com.quizlet.features.setpage.offline.k) c4624g.u.get();
                com.google.firebase.heartbeatinfo.e eVar2 = new com.google.firebase.heartbeatinfo.e(26);
                Context context4 = uVar.q();
                Intrinsics.checkNotNullParameter(context4, "context");
                PackageManager packageManager = context4.getPackageManager();
                Intrinsics.checkNotNullExpressionValue(packageManager, "getPackageManager(...)");
                com.lyft.android.scissors.b bVar3 = new com.lyft.android.scissors.b(packageManager);
                com.google.android.material.shape.e eVar3 = new com.google.android.material.shape.e(26);
                com.google.mlkit.common.internal.model.a aVar5 = new com.google.mlkit.common.internal.model.a(26);
                com.quizlet.features.infra.basestudy.manager.d dVar = (com.quizlet.features.infra.basestudy.manager.d) uVar.D1.get();
                com.quizlet.infra.legacysyncengine.features.properties.d dVarC = c4624g.c();
                com.quizlet.shared.usecase.studiableMetadata.a globalAdFeature = new com.quizlet.shared.usecase.studiableMetadata.a(25);
                Intrinsics.checkNotNullParameter(globalAdFeature, "globalAdFeature");
                com.google.mlkit.vision.documentscanner.internal.c cVar2 = new com.google.mlkit.vision.documentscanner.internal.c(globalAdFeature);
                J jZ = uVar.z();
                com.quizlet.data.interactor.studiablemetadata.b bVarZ = zVar.Z();
                AbstractC5040y abstractC5040yD = com.quizlet.featuregate.injection.a.d();
                com.quizlet.inapp.manager.a aVar6 = (com.quizlet.inapp.manager.a) zVar.v1.get();
                SetPagePerformanceLogger setPagePerformanceLogger = (SetPagePerformanceLogger) c4624g.i.get();
                com.quizlet.remote.model.notes.e eVar4 = new com.quizlet.remote.model.notes.e(c4624g2.g(), new com.quizlet.data.repository.widget.b(new com.quizlet.quizletandroid.ui.group.data.b((com.quizlet.infra.legacysyncengine.net.c) uVar8.Q.get(), uVar8.j(), 1)), new com.quizlet.data.repository.searchexplanations.c(new com.quizlet.quizletandroid.ui.group.data.b((com.quizlet.infra.legacysyncengine.net.c) uVar8.Q.get(), uVar8.j(), 1)), new androidx.compose.foundation.text.input.internal.u(new com.quizlet.quizletandroid.ui.group.data.b((com.quizlet.infra.legacysyncengine.net.c) uVar8.Q.get(), uVar8.j(), 2)), com.quizlet.featuregate.injection.a.d());
                com.quizlet.features.setpage.studymodes.viewmodel.a aVar7 = (com.quizlet.features.setpage.studymodes.viewmodel.a) c4624g.v.get();
                com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G g = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G) c4624g.s.get();
                com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.y yVar = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.y) c4624g.r.get();
                androidx.compose.foundation.text.input.internal.u uVar9 = new androidx.compose.foundation.text.input.internal.u(uVar8.b(), uVar8.l0());
                SignUpWallEventLogger signUpWallEventLogger = new SignUpWallEventLogger((EventLogger) c4624g.b.l0.get());
                com.quizlet.features.setpage.offline.k setPageOfflineManager = (com.quizlet.features.setpage.offline.k) c4624g2.u.get();
                androidx.work.impl.model.c userProperties = uVar8.m0();
                com.google.mlkit.common.internal.model.a setPageProgressFeature = new com.google.mlkit.common.internal.model.a(26);
                io.ktor.client.plugins.api.d getStudySetUseCase = zVar.b0();
                com.quizlet.data.repository.activitycenter.b shareStatusManager = new com.quizlet.data.repository.activitycenter.b(new com.google.firebase.heartbeatinfo.e(26), new com.google.android.material.shape.e(26));
                retrofit2.adapter.rxjava3.d copySetEnabled = new retrofit2.adapter.rxjava3.d(25);
                com.google.firebase.crashlytics.internal.common.j studySetPropertiesFactory = new com.google.firebase.crashlytics.internal.common.j(new com.quizlet.infra.legacysyncengine.features.properties.d((com.quizlet.infra.legacysyncengine.net.c) uVar8.Q.get(), new com.google.firebase.crashlytics.internal.settings.b(new androidx.work.impl.model.v(uVar8.o(), u.v()))), new com.quizlet.local.ormlite.models.set.a(), new assistantMode.utils.studiableMetadata.b(29));
                androidx.work.impl.model.n isSetEditableUseCase = uVar8.e1();
                AbstractC5040y ioDispatcher = com.quizlet.featuregate.injection.a.d();
                C4184z buildConfigModel = com.quizlet.quizletandroid.provider.a.a;
                S6.c(buildConfigModel);
                Intrinsics.checkNotNullParameter(setPageOfflineManager, "setPageOfflineManager");
                Intrinsics.checkNotNullParameter(userProperties, "userProperties");
                Intrinsics.checkNotNullParameter(setPageProgressFeature, "setPageProgressFeature");
                Intrinsics.checkNotNullParameter(getStudySetUseCase, "getStudySetUseCase");
                Intrinsics.checkNotNullParameter(shareStatusManager, "shareStatusManager");
                Intrinsics.checkNotNullParameter(copySetEnabled, "copySetEnabled");
                Intrinsics.checkNotNullParameter(studySetPropertiesFactory, "studySetPropertiesFactory");
                Intrinsics.checkNotNullParameter(isSetEditableUseCase, "isSetEditableUseCase");
                Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
                Intrinsics.checkNotNullParameter(buildConfigModel, "buildConfigModel");
                androidx.compose.runtime.internal.j jVar2 = new androidx.compose.runtime.internal.j();
                jVar2.a = setPageOfflineManager;
                jVar2.b = userProperties;
                jVar2.c = setPageProgressFeature;
                jVar2.d = getStudySetUseCase;
                jVar2.e = shareStatusManager;
                jVar2.f = copySetEnabled;
                jVar2.g = studySetPropertiesFactory;
                jVar2.h = isSetEditableUseCase;
                jVar2.i = ioDispatcher;
                jVar2.j = buildConfigModel;
                com.quizlet.features.infra.folder.menu.viewmodel.m mVar2 = new com.quizlet.features.infra.folder.menu.viewmodel.m(uVar.d(), uVar.w1(), (FolderLogger) uVar.J1.get(), com.quizlet.featuregate.injection.a.d(), uVar.p1());
                com.quizlet.infra.contracts.growthbook.a aVar8 = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
                return new P(m0Var3, j, bVar2, cVarM0, eventLogger3, pVar, searchEventLogger, aVarL, aVar3, hVar, fVar, userInfoCacheL0, vVar, nVarE1, cVar, eVar, fVar2, aVar4, kVar, eVar2, bVar3, eVar3, aVar5, dVar, dVarC, cVar2, jZ, bVarZ, abstractC5040yD, aVar6, setPagePerformanceLogger, eVar4, aVar7, g, yVar, uVar9, signUpWallEventLogger, jVar2, mVar2, AbstractC4178x.i(aVar8, "growthBook", "term_list_compose_android", aVar8), (FolderLogger) uVar.J1.get(), new com.quizlet.shared.usecase.folderstudymaterials.a(26), new com.google.android.material.floatingactionbutton.c(uVar8.g0()));
            case ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND /* 122 */:
                Context contextQ = uVar.q();
                SharedPreferences sharedPreferences = (SharedPreferences) zVar.u1.get();
                u uVar10 = zVar.b;
                com.quizlet.shared.usecase.srs.a aVar9 = uVar10.b;
                return new com.quizlet.inapp.manager.a(contextQ, new com.quizlet.data.repository.searchexplanations.c(uVar10.q(), sharedPreferences));
            case ContentType.USER_GENERATED_LIVE /* 123 */:
                Context context5 = uVar.q();
                Intrinsics.checkNotNullParameter(context5, "context");
                SharedPreferences sharedPreferences2 = context5.getSharedPreferences("APP_REVIEW_SHARED_PREF", 0);
                Intrinsics.checkNotNullExpressionValue(sharedPreferences2, "getSharedPreferences(...)");
                S6.c(sharedPreferences2);
                return sharedPreferences2;
            case 124:
                return new com.quizlet.quizletandroid.ui.preview.viewmodel.g(zVar.a, new com.quizlet.quizletandroid.ui.preview.dataclass.g(zVar.b.q()), new com.quizlet.data.repository.activitycenter.b(zVar.b0(), zVar.d0()), (SearchEventLogger) uVar.G1.get());
            case 125:
                com.quizlet.quizletandroid.interactor.t tVar = (com.quizlet.quizletandroid.interactor.t) uVar.Y0.get();
                com.quizlet.billing.model.a aVar10 = (com.quizlet.billing.model.a) uVar.r0.get();
                com.quizlet.billing.subscriptions.i iVar = (com.quizlet.billing.subscriptions.i) uVar.u0.get();
                com.facebook.z zVarF0 = uVar.F0();
                com.quizlet.data.repository.set.f fVarD0 = uVar.D0();
                C4184z c4184z2 = com.quizlet.quizletandroid.provider.a.a;
                S6.c(c4184z2);
                com.quizlet.features.emailconfirmation.logging.a aVarG0 = zVar.G0();
                com.quizlet.features.infra.logout.viewmodels.d dVarS0 = zVar.s0();
                com.lyft.android.scissors.b bVar4 = new com.lyft.android.scissors.b(new com.quizlet.local.datastore.models.metering.i((InterfaceC1076h) zVar.b.r.get(), 1));
                com.google.android.material.floatingactionbutton.c cVar3 = new com.google.android.material.floatingactionbutton.c(new com.quizlet.local.datastore.models.metering.i((InterfaceC1076h) uVar.r.get(), 1));
                com.quizlet.infra.contracts.growthbook.a aVar11 = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
                return new com.quizlet.features.settings.viewmodels.I(tVar, aVar10, iVar, zVarF0, fVarD0, c4184z2, aVarG0, dVarS0, bVar4, cVar3, AbstractC4178x.i(aVar11, "growthBook", "onetrust_preferences_setting", aVar11), com.quizlet.featuregate.injection.a.d());
            case 126:
                com.features.flashcards.creatormarketing.h hVarH1 = uVar.h1();
                io.ktor.client.plugins.api.d apiClient = zVar.q0();
                com.google.android.gms.internal.appset.e logger = zVar.r0();
                com.quizlet.qutils.string.c state = new com.quizlet.qutils.string.c();
                u uVar11 = zVar.b;
                com.quizlet.login.common.util.b ageUtil = (com.quizlet.login.common.util.b) uVar11.Z0.get();
                com.quizlet.time.b timeUtils = new com.quizlet.time.b();
                com.google.firebase.heartbeatinfo.e getTeacherStatusUseCase = new com.google.firebase.heartbeatinfo.e(new com.quizlet.time.b());
                androidx.work.impl.model.l signUpRequestParentEmailFeature = uVar11.f1();
                androidx.compose.runtime.internal.j handleLoginResponseUseCase = zVar.i0();
                AbstractC5040y ioDispatcher2 = com.quizlet.featuregate.injection.a.d();
                Intrinsics.checkNotNullParameter(apiClient, "apiClient");
                Intrinsics.checkNotNullParameter(logger, "logger");
                Intrinsics.checkNotNullParameter(state, "state");
                Intrinsics.checkNotNullParameter(ageUtil, "ageUtil");
                Intrinsics.checkNotNullParameter(timeUtils, "timeUtils");
                Intrinsics.checkNotNullParameter(getTeacherStatusUseCase, "getTeacherStatusUseCase");
                Intrinsics.checkNotNullParameter(signUpRequestParentEmailFeature, "signUpRequestParentEmailFeature");
                Intrinsics.checkNotNullParameter(handleLoginResponseUseCase, "handleLoginResponseUseCase");
                Intrinsics.checkNotNullParameter(ioDispatcher2, "ioDispatcher");
                com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar2 = new com.onetrust.otpublishers.headless.UI.TVUI.datautils.d();
                dVar2.a = apiClient;
                dVar2.b = logger;
                dVar2.c = state;
                dVar2.d = ageUtil;
                dVar2.e = signUpRequestParentEmailFeature;
                dVar2.f = handleLoginResponseUseCase;
                dVar2.g = ioDispatcher2;
                com.quizlet.login.common.interactors.d dVar3 = new com.quizlet.login.common.interactors.d(uVar11.g1());
                androidx.work.impl.model.c cVar4 = new androidx.work.impl.model.c(uVar11.f1(), (com.quizlet.login.common.util.b) uVar11.Z0.get(), new com.quizlet.time.b());
                com.onetrust.otpublishers.headless.UI.fragment.q qVar = new com.onetrust.otpublishers.headless.UI.fragment.q(new com.quizlet.time.b());
                Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
                return new com.quizlet.login.signup.viewmodel.g(hVarH1, dVar2, dVar3, cVar4, qVar, new com.google.android.gms.internal.mlkit_common.u(29), zVar.a);
            case 127:
                return new com.quizlet.login.signupwall.viewmodel.a(new SignUpWallEventLogger((EventLogger) c4624g.b.l0.get()));
            case 128:
                m0 savedStateHandle = zVar.a;
                com.quizlet.features.match.studyengine.f matchGameManagerFactory = (com.quizlet.features.match.studyengine.f) c4624g.k.get();
                com.quizlet.data.repository.course.membership.c matchStudyModeLoggerFactory = zVar.w0();
                Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
                Intrinsics.checkNotNullParameter(matchGameManagerFactory, "matchGameManagerFactory");
                Intrinsics.checkNotNullParameter(matchStudyModeLoggerFactory, "matchStudyModeLoggerFactory");
                return new com.quizlet.features.match.viewmodel.i(matchGameManagerFactory.a(savedStateHandle), matchStudyModeLoggerFactory.f(savedStateHandle));
            case 129:
                com.quizlet.data.repository.set.f dataSourceProvider = zVar.m();
                Intrinsics.checkNotNullParameter(dataSourceProvider, "dataSourceProvider");
                com.quizlet.infra.legacysyncengine.datasources.p pVar2 = (com.quizlet.infra.legacysyncengine.datasources.p) dataSourceProvider.d;
                Intrinsics.checkNotNullExpressionValue(pVar2, "getRecentSetsDataSource(...)");
                return new com.quizlet.quizletandroid.ui.group.addclassset.viewmodel.c(pVar2);
            case 130:
                return new com.quizlet.features.setpage.studypreview.g(zVar.a, c4624g.j(), new StudySessionQuestionEventLogger.Factory((EventLogger) c4624g.b.l0.get()), (SearchEventLogger) uVar.G1.get(), (SetPagePerformanceLogger) c4624g.i.get(), new com.quizlet.features.setpage.studypreview.data.f(zVar.b.q()), (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get(), uVar.j());
            case 131:
                return new com.quizlet.quizletandroid.ui.subject.viewmodel.m(zVar.a, new com.onetrust.otpublishers.headless.UI.fragment.q(new com.quizlet.featuregate.features.folder.b(zVar.b.m0(), 1)), (x) zVar.E1.get(), new com.quizlet.data.interactor.achievements.f((EventLogger) uVar.l0.get()));
            case 132:
                return new x(this);
            case 133:
                com.quizlet.data.interactor.achievements.f dataStoreFactory = new com.quizlet.data.interactor.achievements.f(new com.quizlet.data.interactor.school.b(uVar.A(), new k(u.Y0()), new com.quizlet.quizletandroid.logging.initializer.a(2)));
                com.quizlet.data.connectivity.a networkStatus = (com.quizlet.data.connectivity.a) uVar.X.get();
                org.slf4j.b logger2 = AbstractC4178x.o((org.slf4j.a) uVar.Y.get(), "loggerFactory", com.quizlet.data.repository.explanations.textbook.a.class, "getLogger(...)");
                Intrinsics.checkNotNullParameter(dataStoreFactory, "dataStoreFactory");
                Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
                Intrinsics.checkNotNullParameter(logger2, "logger");
                com.quizlet.data.repository.explanations.textbook.a aVar12 = new com.quizlet.data.repository.explanations.textbook.a();
                aVar12.a = dataStoreFactory;
                aVar12.b = networkStatus;
                aVar12.c = logger2;
                aVar12.d = new LinkedHashMap();
                return new com.quizlet.explanations.textbook.tableofcontents.viewmodel.b(new com.quizlet.data.repository.widget.b(aVar12, u.v()), new com.quizlet.data.repository.folderset.c(uVar.x0(), u.v(), uVar.l0()), uVar.m0());
            case 134:
                m0 m0Var4 = zVar.a;
                androidx.work.impl.model.e eVarD0 = zVar.d0();
                u uVar12 = zVar.b;
                retrofit2.L l3 = (retrofit2.L) uVar12.a1.get();
                Object objL3 = AbstractC4178x.l(l3, "retrofit", l3, "retrofit", com.quizlet.remote.service.z.class);
                Intrinsics.checkNotNullExpressionValue(objL3, "create(...)");
                com.quizlet.remote.service.z zVar2 = (com.quizlet.remote.service.z) objL3;
                S6.c(zVar2);
                k dataSource2 = new k(zVar2);
                com.quizlet.quizletandroid.ui.login.di.a mapper = new com.quizlet.quizletandroid.ui.login.di.a(3);
                com.quizlet.remote.model.base.b pagingInfoMapper = new com.quizlet.remote.model.base.b();
                Intrinsics.checkNotNullParameter(dataSource2, "dataSource");
                Intrinsics.checkNotNullParameter(mapper, "mapper");
                Intrinsics.checkNotNullParameter(pagingInfoMapper, "pagingInfoMapper");
                com.quizlet.data.interactor.set.c cVar5 = new com.quizlet.data.interactor.set.c();
                cVar5.a = dataSource2;
                cVar5.b = mapper;
                cVar5.c = pagingInfoMapper;
                com.google.android.datatransport.cct.internal.s database = uVar12.R0();
                ModelIdentityProvider modelIdentityProvider = (ModelIdentityProvider) uVar12.B.get();
                com.quizlet.shared.usecase.folderstudymaterials.d mapper2 = new com.quizlet.shared.usecase.folderstudymaterials.d(28);
                Intrinsics.checkNotNullParameter(database, "database");
                Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
                Intrinsics.checkNotNullParameter(mapper2, "mapper");
                com.quizlet.data.repository.login.a aVar13 = new com.quizlet.data.repository.login.a();
                aVar13.a = modelIdentityProvider;
                aVar13.b = mapper2;
                aVar13.c = (com.quizlet.data.interactor.achievements.f) database.g;
                return new com.quizlet.features.setpage.termlist.viewmodel.j(m0Var4, new com.google.android.gms.internal.appset.e(eVarD0, new com.quizlet.data.repository.widget.b(new com.quizlet.data.repository.selectedterm.f(cVar5, aVar13, com.quizlet.featuregate.injection.a.d(), AbstractC4178x.o((org.slf4j.a) uVar12.Y.get(), "loggerFactory", com.quizlet.data.repository.selectedterm.f.class, "getLogger(...)")), uVar12.l0()), zVar.O()), new com.quizlet.data.interactor.course.a(new com.google.mlkit.vision.documentscanner.internal.c(new C4567d((InterfaceC1076h) uVar12.p1.get(), 1), (byte) 0)), new com.quizlet.shared.usecase.folderstudymaterials.d(27), (com.quizlet.quizletandroid.managers.audio.h) uVar.f0.get(), new androidx.work.impl.model.v(uVar12.d1(), zVar.c.g()));
            case 135:
                return new com.quizlet.features.setpage.terms.viewmodel.c(zVar.a, (com.quizlet.infra.legacysyncengine.datasources.factory.b) c4624g.p.get(), c4624g.e(), zVar.O(), uVar.Z(), (SetPagePerformanceLogger) c4624g.i.get());
            case 136:
                return new com.quizlet.search.viewmodels.M(zVar.a, zVar.d0(), zVar.f0(), (SearchEventLogger) uVar.G1.get());
            case 137:
                m0 m0Var5 = zVar.a;
                EventLogger eventLogger4 = (EventLogger) uVar.l0.get();
                Intrinsics.checkNotNullParameter(eventLogger4, "eventLogger");
                StudyModeEventLogger studyModeEventLogger = new StudyModeEventLogger(eventLogger4, A1.TEST);
                u uVar13 = zVar.b;
                return new com.quizlet.quizletandroid.ui.studymodes.testmode.start.A(m0Var5, studyModeEventLogger, new com.google.mlkit.vision.documentscanner.internal.c(new androidx.work.impl.model.v((DatabaseHelper) uVar13.v.get(), com.quizlet.featuregate.injection.a.d())), new com.quizlet.data.interactor.achievements.f(uVar13.W()), new com.google.firebase.crashlytics.internal.settings.b(uVar13.W()), (com.quizlet.features.infra.basestudy.manager.a) c4624g.j.get());
            case 138:
                return new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t(uVar.m0(), (com.quizlet.quizletandroid.managers.audio.h) uVar.f0.get());
            case 139:
                m0 m0Var6 = zVar.a;
                com.quizlet.features.infra.basestudy.manager.a aVar14 = (com.quizlet.features.infra.basestudy.manager.a) c4624g.j.get();
                com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.c cVar6 = (com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.c) c4624g.m.get();
                com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.e eVar5 = (com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.e) c4624g.w.get();
                u uVar14 = zVar.b;
                return new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G(m0Var6, aVar14, cVar6, eVar5, new com.quizlet.data.interactor.school.b(uVar14.w0(), new com.lyft.android.scissors.b(uVar14.x1())), c4624g.k(), (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get(), (com.quizlet.quizletandroid.managers.audio.h) uVar.f0.get(), new com.quizlet.featuregate.features.flexiblegrading.a(2), uVar.m0(), c4624g.c(), zVar.S(), new com.quizlet.quizletandroid.ui.studymodes.testmode.logging.a((EventLogger) uVar14.l0.get()), new com.quizlet.features.questiontypes.grading.a((EventLogger) uVar14.l0.get()), new com.quizlet.data.repository.searchexplanations.c(zVar.Z(), com.quizlet.featuregate.injection.a.d()), (com.quizlet.data.connectivity.a) uVar.X.get());
            case 140:
                return new com.quizlet.explanations.textbook.viewmodel.c(zVar.B(), zVar.H0(), (SearchEventLogger) uVar.G1.get(), uVar.m0(), (FolderLogger) uVar.J1.get());
            case ModuleDescriptor.MODULE_VERSION /* 141 */:
                return new com.quizlet.features.questiontypes.truefalse.l(zVar.a, (com.quizlet.quizletandroid.ui.studymodes.grader.b) c4624g.n.get(), (com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a) c4624g.o.get(), new com.quizlet.data.repository.set.f(new com.quizlet.features.questiontypes.basequestion.c()), (QuestionEventLogger) c4624g.h.get(), (com.quizlet.quizletandroid.managers.audio.h) uVar.f0.get());
            case 142:
                m0 m0Var7 = zVar.a;
                com.google.android.gms.internal.appset.e eVarN0 = zVar.N0();
                u uVar15 = zVar.b;
                return new com.quizlet.features.universaluploadflow.flashcards.viewmodel.e(m0Var7, eVarN0, new l1(new com.google.firebase.crashlytics.internal.settings.b(uVar15.t1()), uVar15.j()), zVar.L0());
            case 143:
                return new com.quizlet.data.interactor.universaluploadflow.d(uVar.t1());
            case 144:
                return new com.quizlet.data.interactor.universaluploadflow.b(uVar.E(), uVar.t1());
            case 145:
                return new com.quizlet.data.interactor.universaluploadflow.c(uVar.t1());
            case 146:
                return new com.quizlet.features.universaluploadflow.pastetext.viewmodel.d(zVar.a, zVar.N0(), zVar.L0());
            case 147:
                m0 m0Var8 = zVar.a;
                com.google.android.gms.internal.appset.e eVarN02 = zVar.N0();
                u uVar16 = zVar.b;
                retrofit2.L l4 = (retrofit2.L) uVar16.a1.get();
                Object objL4 = AbstractC4178x.l(l4, "retrofit", l4, "retrofit", com.quizlet.remote.service.k.class);
                Intrinsics.checkNotNullExpressionValue(objL4, "create(...)");
                com.quizlet.remote.service.k kVar2 = (com.quizlet.remote.service.k) objL4;
                S6.c(kVar2);
                return new com.quizlet.features.universaluploadflow.viewmodel.g(m0Var8, eVarN02, new androidx.work.impl.model.l(new com.google.android.material.floatingactionbutton.c(new com.quizlet.data.repository.classfolder.e(kVar2, new com.quizlet.quizletandroid.ui.profile.b(), com.quizlet.featuregate.injection.a.d())), uVar16.l0()), zVar.L0(), uVar.E(), uVar.l0(), uVar.J0());
            case 148:
                return new com.quizlet.upgrade.ui.confirmation.c(zVar.a);
            case 149:
                return new com.quizlet.upgrade.viewmodel.h(zVar.a, uVar.e0(), new com.quizlet.quizletandroid.ui.activitycenter.models.a(), uVar.R(), (com.quizlet.billing.model.a) uVar.r0.get(), new androidx.webkit.internal.p((com.quizlet.billing.model.a) zVar.b.r0.get()), c4624g.b());
            case 150:
                return new com.quizlet.upgrade.viewmodel.k(uVar.R(), uVar.d0());
            case 151:
                m0 m0Var9 = zVar.a;
                com.lyft.android.scissors.b bVarE0 = uVar.e0();
                com.quizlet.features.emailconfirmation.logging.a aVarD0 = uVar.d0();
                com.lyft.android.scissors.b billingUserManager = uVar.e0();
                com.quizlet.features.emailconfirmation.logging.a billingEventLogger = uVar.d0();
                kotlinx.coroutines.scheduling.e dispatcher = O.a;
                S6.c(dispatcher);
                Intrinsics.checkNotNullParameter(billingUserManager, "billingUserManager");
                Intrinsics.checkNotNullParameter(billingEventLogger, "billingEventLogger");
                Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
                com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar4 = new com.onetrust.otpublishers.headless.UI.TVUI.datautils.d();
                dVar4.a = billingUserManager;
                dVar4.c = billingEventLogger;
                dVar4.d = dispatcher;
                dVar4.e = new Y(com.quizlet.upgrade.manager.f.b);
                dVar4.f = new X(1);
                return new com.quizlet.upgrade.viewmodel.n(m0Var9, bVarE0, aVarD0, dVar4);
            case 152:
                m0 m0Var10 = zVar.a;
                com.quizlet.features.notes.logging.f fVarX0 = zVar.x0();
                com.quizlet.infra.contracts.growthbook.a growthBook = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
                Intrinsics.checkNotNullParameter(growthBook, "growthBook");
                com.quizlet.data.repository.explanations.question.a aVar15 = new com.quizlet.data.repository.explanations.question.a(growthBook, "study_guide_upload_character_minimum_android", (Integer) 100);
                com.quizlet.infra.contracts.growthbook.a growthBook2 = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
                Intrinsics.checkNotNullParameter(growthBook2, "growthBook");
                com.quizlet.data.repository.explanations.question.a aVar16 = new com.quizlet.data.repository.explanations.question.a(growthBook2, "study_guide_upload_character_maximum_android", Integer.valueOf(ConnectivityType.UNKNOWN));
                com.quizlet.infra.contracts.growthbook.a growthBook3 = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
                Intrinsics.checkNotNullParameter(growthBook3, "growthBook");
                com.quizlet.data.repository.explanations.question.a aVar17 = new com.quizlet.data.repository.explanations.question.a(growthBook3, "study_guide_upload_file_size_maximum_android", (Integer) 25600);
                com.google.firebase.crashlytics.internal.settings.b bVarB = c4624g.b();
                u uVar17 = zVar.b;
                com.quizlet.features.notes.a aVar18 = new com.quizlet.features.notes.a((EventLogger) uVar17.l0.get(), 0);
                com.quizlet.data.interactor.metering.b bVarV = zVar.V();
                long j2 = uVar.j();
                com.quizlet.infra.contracts.growthbook.a growthBook4 = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
                Intrinsics.checkNotNullParameter(growthBook4, "growthBook");
                com.quizlet.data.repository.explanations.question.a aVar19 = new com.quizlet.data.repository.explanations.question.a(growthBook4, "study_guide_metering_num_uploads_android", (Integer) 5);
                long j3 = uVar17.j();
                com.quizlet.data.repository.user.e userRepository = uVar17.v1();
                com.quizlet.shared.usecase.studynotes.o createFromFilesUseCase = (com.quizlet.shared.usecase.studynotes.o) com.quizlet.shared.usecase.di.f.a.getValue();
                S6.c(createFromFilesUseCase);
                AbstractC5040y dispatcher2 = com.quizlet.featuregate.injection.a.d();
                com.quizlet.data.repository.login.a getStudyNotesByIdUseCase = zVar.a0();
                Intrinsics.checkNotNullParameter(userRepository, "userRepository");
                Intrinsics.checkNotNullParameter(createFromFilesUseCase, "createFromFilesUseCase");
                Intrinsics.checkNotNullParameter(dispatcher2, "dispatcher");
                Intrinsics.checkNotNullParameter(getStudyNotesByIdUseCase, "getStudyNotesByIdUseCase");
                androidx.work.impl.background.greedy.d dVar5 = new androidx.work.impl.background.greedy.d();
                dVar5.a = j3;
                dVar5.b = userRepository;
                dVar5.c = createFromFilesUseCase;
                dVar5.d = dispatcher2;
                dVar5.e = getStudyNotesByIdUseCase;
                return new com.quizlet.features.notes.upload.viewmodels.k(m0Var10, fVarX0, aVar15, aVar16, aVar17, bVarB, aVar18, bVarV, j2, aVar19, dVar5, uVar.E(), new com.google.firebase.crashlytics.internal.settings.b(new com.onetrust.otpublishers.headless.UI.fragment.q(new com.quizlet.data.repository.qclass.c(uVar.K(), new com.quizlet.quizletandroid.ui.login.di.a(2)))));
            case 153:
                return new com.quizlet.upgrade.upsell.viewmodel.c(c4624g.l());
            case 154:
                com.quizlet.quizletandroid.interactor.t tVar2 = (com.quizlet.quizletandroid.interactor.t) uVar.Y0.get();
                com.google.firebase.messaging.p pVarA = c4624g.a();
                com.quizlet.infra.legacysyncengine.managers.d dVar6 = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
                Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
                com.google.mlkit.common.sdkinternal.model.a aVar20 = new com.google.mlkit.common.sdkinternal.model.a(26);
                com.quizlet.features.userprofile.a aVar21 = new com.quizlet.features.userprofile.a((EventLogger) zVar.b.l0.get());
                com.quizlet.data.interactor.course.a aVar22 = new com.quizlet.data.interactor.course.a((Braze) uVar.W0.get());
                Context context6 = uVar.q();
                Intrinsics.checkNotNullParameter(context6, "context");
                SharedPreferences sharedPreferences3 = context6.getSharedPreferences("BRAZE_EVENT_SHARED_PREF", 0);
                Intrinsics.checkNotNullExpressionValue(sharedPreferences3, "getSharedPreferences(...)");
                S6.c(sharedPreferences3);
                return new com.quizlet.features.userprofile.data.x(tVar2, pVarA, dVar6, aVar20, aVar21, new com.quizlet.quizletandroid.braze.events.b(aVar22, new com.quizlet.db.b(sharedPreferences3, 2), uVar.l0()), c4624g.l(), new com.quizlet.featuregate.features.home.a(), c4624g.d(), uVar.m0());
            case 155:
                return new com.quizlet.features.questiontypes.written.o(zVar.a, new androidx.work.impl.model.l(zVar.a, (com.quizlet.quizletandroid.ui.studymodes.grader.b) zVar.c.n.get(), new com.quizlet.features.questiontypes.grading.a((EventLogger) zVar.b.l0.get())), (com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a) c4624g.o.get(), (com.quizlet.quizletandroid.managers.audio.h) uVar.f0.get(), (QuestionEventLogger) c4624g.h.get(), (EventLogger) uVar.l0.get(), new com.quizlet.features.questiontypes.basequestion.c());
            default:
                throw new AssertionError(i);
        }
    }
}
