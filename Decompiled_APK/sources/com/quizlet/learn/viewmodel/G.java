package com.quizlet.learn.viewmodel;

import android.os.CountDownTimer;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import assistantMode.refactored.types.RoundProgress;
import assistantMode.refactored.types.TaskRoundProgress;
import assistantMode.types.aliases.ExperimentConfiguration;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.quizlet.ads.data.AdDataType;
import com.quizlet.data.model.C4127f1;
import com.quizlet.data.model.C4179x0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBQuestionAttribute;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUserStudyable;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBQuestionAttributeFields;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.learn.LearnEventAction;
import com.quizlet.eventlogger.features.learn.LearnEventLog;
import com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.C1;
import com.quizlet.generated.enums.E1;
import com.quizlet.generated.enums.G1;
import com.quizlet.generated.enums.P;
import com.quizlet.generated.enums.S;
import com.quizlet.learn.StudyEngineException;
import com.quizlet.learn.data.C4544i;
import com.quizlet.learn.data.C4546k;
import com.quizlet.learn.data.C4547l;
import com.quizlet.learn.data.C4548m;
import com.quizlet.learn.data.C4549n;
import com.quizlet.learn.data.H;
import com.quizlet.learn.data.I;
import com.quizlet.learn.data.L;
import com.quizlet.learn.settings.data.LearnSettingsResult;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.StudiableCheckpoint;
import com.quizlet.studiablemodels.StudiableMeteringData;
import com.quizlet.studiablemodels.StudiableRoundProgress;
import com.quizlet.studiablemodels.StudiableStep;
import com.quizlet.studiablemodels.StudiableTaskTotalProgress;
import com.quizlet.studiablemodels.StudiableTotalProgress;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Metadata;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.V;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class G extends com.quizlet.viewmodel.a {
    public static final List D1 = kotlin.collections.B.j(E1.PROMPT_TERM_SIDES, E1.ANSWER_TERM_SIDES, E1.ASSISTANT_MODE_QUESTION_TYPES);
    public final com.quizlet.data.connectivity.a A;
    public final androidx.compose.ui.text.font.o A1;
    public final com.google.android.gms.internal.mlkit_common.u B;
    public final com.quizlet.learn.ads.h B1;
    public final com.quizlet.data.repository.user.a C;
    public final C4203d C1;
    public final androidx.work.impl.model.l D;
    public final com.quizlet.data.repository.user.a E;
    public final com.quizlet.data.repository.user.a F;
    public final com.quizlet.learn.usecase.d G;
    public final com.quizlet.data.interactor.achievements.f H;
    public final com.google.firebase.crashlytics.internal.settings.b I;
    public final s0 J;
    public final s0 K;
    public final Y L;
    public final X M;
    public final X V;
    public final X W;
    public final X X;
    public final Y Y;
    public final com.quizlet.features.infra.basestudy.manager.f Z;
    public final int c1;
    public final m0 d;
    public final String d1;
    public final com.quizlet.infra.legacysyncengine.net.f e;
    public final long e1;
    public final com.quizlet.data.repository.progress.b f;
    public final InterfaceC4176w0 f1;
    public final com.quizlet.features.infra.basestudy.data.models.onboarding.a g;
    public boolean g1;
    public final com.quizlet.learn.checkpoint.a h;
    public final com.quizlet.features.infra.studysetting.datasource.a h1;
    public final UserInfoCache i;
    public final com.quizlet.features.infra.studysetting.datasource.a i1;
    public final com.quizlet.featuregate.features.studymodes.learn.a j;
    public DBSession j1;
    public final com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a k;
    public io.reactivex.rxjava3.core.i k1;
    public final io.reactivex.rxjava3.core.o l;
    public StudiableStep l1;
    public final io.reactivex.rxjava3.core.o m;
    public final ArrayList m1;
    public final com.quizlet.infra.legacysyncengine.managers.d n;
    public final ArrayList n1;
    public final com.quizlet.qutils.i18n.a o;
    public C4127f1 o1;
    public final com.quizlet.infra.legacysyncengine.managers.i p;
    public AtomicReference p1;
    public final androidx.work.impl.model.c q;
    public final StudyModeEventLogger q1;
    public final com.quizlet.learn.logging.a r;
    public Map r1;
    public final com.quizlet.infra.legacysyncengine.features.properties.d s;
    public int s1;
    public final com.quizlet.data.interactor.school.b t;
    public boolean t1;
    public final com.quizlet.data.interactor.set.c u;
    public boolean u1;
    public final com.quizlet.time.b v;
    public com.quizlet.featuregate.features.studymodes.learn.b v1;
    public final StudyModeMeteringEventLogger w;
    public Boolean w1;
    public final com.quizlet.features.infra.basestudy.utils.c x;
    public Boolean x1;
    public final androidx.compose.foundation.text.input.internal.u y;
    public final ExperimentConfiguration y1;
    public final com.quizlet.data.repository.searchexplanations.c z;
    public boolean z1;

    public G(m0 savedStateHandle, com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory, com.quizlet.infra.legacysyncengine.net.f syncDispatcher, com.quizlet.data.repository.progress.b studiableStepRepository, com.quizlet.features.infra.basestudy.data.models.onboarding.a onboardingState, com.quizlet.learn.checkpoint.a reviewAllTermsTracker, UserInfoCache userInfoCache, com.quizlet.featuregate.features.studymodes.learn.a tasksExperiment, com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a studyQuestionAnswerManager, io.reactivex.rxjava3.core.o computationScheduler, io.reactivex.rxjava3.core.o mainThreadScheduler, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, com.quizlet.infra.legacysyncengine.managers.i saveManager, com.quizlet.infra.legacysyncengine.net.c loader, androidx.work.impl.model.c userProperties, com.quizlet.data.interactor.progress.c progressResetUseCase, com.quizlet.learn.logging.a learnEventLogger, EventLogger eventLogger, com.quizlet.infra.legacysyncengine.features.properties.d studySetProperties, com.quizlet.data.interactor.school.b saveMeteringInfoUseCase, com.quizlet.data.interactor.set.c testMeteringDataUseCase, com.quizlet.quizletandroid.w studyAdManagerFactory, StudyModeMeteringEventLogger meteringLogger, androidx.compose.foundation.text.input.internal.u achievementsEventUseCase, com.quizlet.data.repository.searchexplanations.c getStudyModeStudiableMetadataUseCase, com.quizlet.data.connectivity.a networkConnectivityManager, com.google.android.gms.internal.mlkit_common.u shouldGenerateNewPromptUseCase, com.quizlet.data.repository.user.a learnCheckpointSettingsFeature, androidx.work.impl.model.l checkLearn1stRoundEasierEligibilityUseCase, com.quizlet.data.repository.user.a learnSettingsRefresh, com.quizlet.data.repository.user.a improveSmartGradingFeature, com.quizlet.learn.usecase.d getWrittenGradingOptionsUseCase, com.quizlet.data.interactor.achievements.f getSettingsTermValueUseCase, com.google.firebase.crashlytics.internal.settings.b getSettingsDefinitionValueUseCase) {
        J jF;
        com.quizlet.qutils.i18n.a localeUtil = com.quizlet.qutils.i18n.a.a;
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        com.quizlet.features.infra.basestudy.utils.c studiableDataFactory = com.quizlet.features.infra.basestudy.utils.c.a;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        Intrinsics.checkNotNullParameter(studiableStepRepository, "studiableStepRepository");
        Intrinsics.checkNotNullParameter(onboardingState, "onboardingState");
        Intrinsics.checkNotNullParameter(reviewAllTermsTracker, "reviewAllTermsTracker");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(tasksExperiment, "tasksExperiment");
        Intrinsics.checkNotNullParameter(studyQuestionAnswerManager, "studyQuestionAnswerManager");
        Intrinsics.checkNotNullParameter(computationScheduler, "computationScheduler");
        Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(localeUtil, "localeUtil");
        Intrinsics.checkNotNullParameter(saveManager, "saveManager");
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(progressResetUseCase, "progressResetUseCase");
        Intrinsics.checkNotNullParameter(learnEventLogger, "learnEventLogger");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(studySetProperties, "studySetProperties");
        Intrinsics.checkNotNullParameter(saveMeteringInfoUseCase, "saveMeteringInfoUseCase");
        Intrinsics.checkNotNullParameter(testMeteringDataUseCase, "testMeteringDataUseCase");
        Intrinsics.checkNotNullParameter(studyAdManagerFactory, "studyAdManagerFactory");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        Intrinsics.checkNotNullParameter(meteringLogger, "meteringLogger");
        Intrinsics.checkNotNullParameter(studiableDataFactory, "studiableDataFactory");
        Intrinsics.checkNotNullParameter(achievementsEventUseCase, "achievementsEventUseCase");
        Intrinsics.checkNotNullParameter(getStudyModeStudiableMetadataUseCase, "getStudyModeStudiableMetadataUseCase");
        Intrinsics.checkNotNullParameter(networkConnectivityManager, "networkConnectivityManager");
        Intrinsics.checkNotNullParameter(shouldGenerateNewPromptUseCase, "shouldGenerateNewPromptUseCase");
        Intrinsics.checkNotNullParameter(learnCheckpointSettingsFeature, "learnCheckpointSettingsFeature");
        Intrinsics.checkNotNullParameter(checkLearn1stRoundEasierEligibilityUseCase, "checkLearn1stRoundEasierEligibilityUseCase");
        Intrinsics.checkNotNullParameter(learnSettingsRefresh, "learnSettingsRefresh");
        Intrinsics.checkNotNullParameter(improveSmartGradingFeature, "improveSmartGradingFeature");
        Intrinsics.checkNotNullParameter(getWrittenGradingOptionsUseCase, "getWrittenGradingOptionsUseCase");
        Intrinsics.checkNotNullParameter(getSettingsTermValueUseCase, "getSettingsTermValueUseCase");
        Intrinsics.checkNotNullParameter(getSettingsDefinitionValueUseCase, "getSettingsDefinitionValueUseCase");
        this.d = savedStateHandle;
        this.e = syncDispatcher;
        this.f = studiableStepRepository;
        this.g = onboardingState;
        this.h = reviewAllTermsTracker;
        this.i = userInfoCache;
        this.j = tasksExperiment;
        this.k = studyQuestionAnswerManager;
        this.l = computationScheduler;
        this.m = mainThreadScheduler;
        this.n = loggedInUserManager;
        this.o = localeUtil;
        this.p = saveManager;
        this.q = userProperties;
        this.r = learnEventLogger;
        this.s = studySetProperties;
        this.t = saveMeteringInfoUseCase;
        this.u = testMeteringDataUseCase;
        this.v = timeProvider;
        this.w = meteringLogger;
        this.x = studiableDataFactory;
        this.y = achievementsEventUseCase;
        this.z = getStudyModeStudiableMetadataUseCase;
        this.A = networkConnectivityManager;
        this.B = shouldGenerateNewPromptUseCase;
        this.C = learnCheckpointSettingsFeature;
        this.D = checkLearn1stRoundEasierEligibilityUseCase;
        this.E = learnSettingsRefresh;
        this.F = improveSmartGradingFeature;
        this.G = getWrittenGradingOptionsUseCase;
        this.H = getSettingsTermValueUseCase;
        this.I = getSettingsDefinitionValueUseCase;
        s0 s0VarC = e0.c(com.quizlet.learn.ui.toolbar.h.b);
        this.J = s0VarC;
        this.K = s0VarC;
        this.L = new Y();
        this.M = new X(1);
        this.V = new X(1);
        this.W = new X(1);
        this.X = new X(1);
        this.Y = new Y(Boolean.FALSE);
        com.quizlet.features.infra.basestudy.manager.f fVarA = studyModeManagerFactory.a(savedStateHandle);
        this.Z = fVarA;
        Object objA = savedStateHandle.a("learnModeBehavior");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.c1 = ((Number) objA).intValue();
        Object objA2 = savedStateHandle.a("studyableModelTitle");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.d1 = (String) objA2;
        Object objA3 = savedStateHandle.a("studyableModelLocalId");
        if (objA3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.e1 = ((Number) objA3).longValue();
        Object objA4 = savedStateHandle.a("meteredEvent");
        if (objA4 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.f1 = (InterfaceC4176w0) objA4;
        Object objA5 = savedStateHandle.a("SHOW_ONBOARDING_KEY");
        if (objA5 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.g1 = ((Boolean) objA5).booleanValue();
        this.m1 = new ArrayList();
        this.n1 = new ArrayList();
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        Intrinsics.checkNotNullExpressionValue(dVar, "empty(...)");
        this.p1 = dVar;
        A1 a1 = fVarA.o;
        this.q1 = new StudyModeEventLogger(eventLogger, a1);
        this.r1 = V.c();
        StudiableRoundProgress studiableRoundProgressK = K();
        this.s1 = studiableRoundProgressK != null ? studiableRoundProgressK.b : 7;
        this.y1 = new ExperimentConfiguration();
        this.A1 = new androidx.compose.ui.text.font.o(C5041z.a, 10);
        long personId = userInfoCache.getPersonId();
        Intrinsics.checkNotNullParameter(loader, "loader");
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.SESSION);
        bVar.b(Long.valueOf(personId), DBSessionFields.PERSON);
        bVar.b(Long.valueOf(G1.SET.b()), DBSessionFields.ITEM_TYPE);
        bVar.e(DBSessionFields.STUDYABLE, DBStudySetFields.CREATOR);
        com.quizlet.features.infra.studysetting.datasource.a aVar = new com.quizlet.features.infra.studysetting.datasource.a(loader, bVar.a());
        aVar.f();
        com.quizlet.infra.legacysyncengine.net.b bVar2 = com.quizlet.infra.legacysyncengine.net.b.a;
        aVar.b.c(aVar.c, Z.b(bVar2));
        com.quizlet.features.infra.studysetting.datasource.a aVar2 = new com.quizlet.features.infra.studysetting.datasource.a(loader, fVarA.u, userInfoCache.getPersonId(), a1);
        this.h1 = aVar2;
        aVar2.f();
        aVar2.b.c(aVar2.c, Z.b(bVar2));
        long personId2 = userInfoCache.getPersonId();
        Intrinsics.checkNotNullParameter(loader, "loader");
        com.quizlet.infra.legacysyncengine.orm.b bVar3 = new com.quizlet.infra.legacysyncengine.orm.b(Models.QUESTION_ATTRIBUTE);
        Relationship<DBQuestionAttribute, DBStudySet> relationship = DBQuestionAttributeFields.SET_ID;
        long j = fVarA.u;
        bVar3.b(Long.valueOf(j), relationship);
        bVar3.b(Long.valueOf(personId2), DBQuestionAttributeFields.PERSON_ID);
        com.quizlet.features.infra.studysetting.datasource.a aVar3 = new com.quizlet.features.infra.studysetting.datasource.a(loader, bVar3.a());
        this.i1 = aVar3;
        aVar3.f();
        aVar3.b.c(aVar3.c, Z.b(bVar2));
        com.quizlet.infra.legacysyncengine.features.properties.d.c(studySetProperties, j);
        long personId3 = userInfoCache.getPersonId();
        io.reactivex.rxjava3.subjects.r stopToken = this.c;
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        long jCurrentTimeMillis = System.currentTimeMillis();
        long j2 = com.quizlet.data.interactor.progress.c.e + 45000;
        long j3 = fVarA.u;
        if (jCurrentTimeMillis < j2) {
            jF = new J(((androidx.work.impl.model.c) progressResetUseCase.c).b(stopToken, new com.quizlet.data.interactor.progress.a(progressResetUseCase, personId3, j3, 1)), new com.google.android.material.floatingactionbutton.c(progressResetUseCase, 10), 5);
            Intrinsics.checkNotNullExpressionValue(jF, "onErrorReturn(...)");
        } else {
            jF = progressResetUseCase.f(personId3, j3, stopToken);
        }
        l lVar = new l(this, 0);
        com.quizlet.billing.manager.d dVar2 = new com.quizlet.billing.manager.d(timber.log.c.a, 5);
        io.reactivex.rxjava3.internal.functions.b bVar4 = io.reactivex.rxjava3.internal.functions.d.c;
        io.reactivex.rxjava3.disposables.b bVarU = jF.u(lVar, dVar2, bVar4);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        Intrinsics.checkNotNullParameter(bVarU, "<this>");
        A(bVarU);
        com.google.mlkit.common.sdkinternal.model.a aVar4 = com.quizlet.ads.c.b;
        studyAdManagerFactory.getClass();
        com.quizlet.quizletandroid.y yVar = studyAdManagerFactory.a;
        com.quizlet.quizletandroid.u uVar = yVar.c.b;
        com.quizlet.learn.ads.f fVar = new com.quizlet.learn.ads.f(uVar.q(), new com.google.mlkit.vision.documentscanner.internal.c(uVar.v0), uVar.o0(), new com.quizlet.learn.ads.c(uVar.q(), uVar.c1), (com.quizlet.ads.g) uVar.v1.get());
        com.google.firebase.crashlytics.internal.settings.b bVar5 = new com.google.firebase.crashlytics.internal.settings.b();
        com.quizlet.quizletandroid.u uVar2 = yVar.a;
        com.quizlet.learn.ads.h hVar = new com.quizlet.learn.ads.h(fVar, bVar5, uVar2.m0(), uVar2.q());
        this.B1 = hVar;
        io.reactivex.rxjava3.disposables.b bVarU2 = hVar.f.u(new l(this, 1), io.reactivex.rxjava3.internal.functions.d.e, bVar4);
        Intrinsics.checkNotNullExpressionValue(bVarU2, "subscribe(...)");
        Intrinsics.checkNotNullParameter(bVarU2, "<this>");
        A(bVarU2);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new m(this, null), 3);
        this.C1 = new C4203d(this);
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object B(com.quizlet.learn.viewmodel.G r10, com.quizlet.learn.data.C4537b r11, java.util.List r12, java.util.List r13, boolean r14, kotlin.coroutines.jvm.internal.c r15) throws java.lang.Throwable {
        /*
            r10.getClass()
            boolean r0 = r15 instanceof com.quizlet.learn.viewmodel.q
            if (r0 == 0) goto L17
            r0 = r15
            com.quizlet.learn.viewmodel.q r0 = (com.quizlet.learn.viewmodel.q) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L17
            int r1 = r1 - r2
            r0.n = r1
        L15:
            r8 = r0
            goto L1d
        L17:
            com.quizlet.learn.viewmodel.q r0 = new com.quizlet.learn.viewmodel.q
            r0.<init>(r10, r15)
            goto L15
        L1d:
            java.lang.Object r15 = r8.l
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.n
            r9 = 1
            if (r1 == 0) goto L38
            if (r1 != r9) goto L30
            com.quizlet.learn.data.b r11 = r8.k
            com.quizlet.learn.viewmodel.G r10 = r8.j
            androidx.glance.appwidget.protobuf.Z.e(r15)
            goto L57
        L30:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            com.quizlet.features.infra.studysetting.data.QuestionSettings r5 = r10.I()
            com.quizlet.features.infra.basestudy.manager.f r15 = r10.Z
            com.quizlet.generated.enums.A1 r6 = r15.o
            r8.j = r10
            r8.k = r11
            r8.n = r9
            r1 = r10
            r2 = r11
            r3 = r12
            r4 = r13
            r7 = r14
            java.lang.Object r15 = r1.J(r2, r3, r4, r5, r6, r7, r8)
            if (r15 != r0) goto L55
            return r0
        L55:
            r10 = r1
            r11 = r2
        L57:
            com.quizlet.studiablemodels.StudiableStep r15 = (com.quizlet.studiablemodels.StudiableStep) r15
            java.util.List r12 = r11.d
            r10.getClass()
            boolean r10 = r15 instanceof com.quizlet.studiablemodels.StudiableQuestion
            r13 = 0
            if (r10 != 0) goto L65
        L63:
            r9 = r13
            goto Lb5
        L65:
            r10 = r15
            com.quizlet.studiablemodels.StudiableQuestion r10 = (com.quizlet.studiablemodels.StudiableQuestion) r10
            boolean r14 = r10 instanceof com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion
            if (r14 != 0) goto L70
            boolean r14 = r10 instanceof com.quizlet.studiablemodels.WrittenStudiableQuestion
            if (r14 == 0) goto L63
        L70:
            int r14 = r12.size()
            java.util.ListIterator r12 = r12.listIterator(r14)
        L78:
            boolean r14 = r12.hasPrevious()
            r0 = 0
            if (r14 == 0) goto L95
            java.lang.Object r14 = r12.previous()
            r1 = r14
            com.quizlet.db.data.models.persisted.DBAnswer r1 = (com.quizlet.db.data.models.persisted.DBAnswer) r1
            long r1 = r1.getTermId()
            com.quizlet.studiablemodels.StudiableQuestionMetadata r3 = r10.a()
            long r3 = r3.b
            int r1 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r1 != 0) goto L78
            goto L96
        L95:
            r14 = r0
        L96:
            com.quizlet.db.data.models.persisted.DBAnswer r14 = (com.quizlet.db.data.models.persisted.DBAnswer) r14
            if (r14 == 0) goto La2
            int r10 = r14.getCorrectness()
            java.lang.Integer r0 = java.lang.Integer.valueOf(r10)
        La2:
            if (r0 != 0) goto La5
            goto Lab
        La5:
            int r10 = r0.intValue()
            if (r10 == 0) goto Lb5
        Lab:
            if (r0 != 0) goto Lae
            goto L63
        Lae:
            int r10 = r0.intValue()
            r12 = 3
            if (r10 != r12) goto L63
        Lb5:
            com.quizlet.learn.data.O r10 = new com.quizlet.learn.data.O
            java.util.List r11 = r11.a
            int r11 = r11.size()
            r10.<init>(r15, r11, r9)
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.learn.viewmodel.G.B(com.quizlet.learn.viewmodel.G, com.quizlet.learn.data.b, java.util.List, java.util.List, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final void C(G g, Throwable th) {
        g.W.j(com.quizlet.learn.data.x.a);
        timber.log.c.a.e(new StudyEngineException(AbstractC0147y.d("Error while generating study step: ", th.getMessage()), th));
    }

    public static void G(G g, boolean z, int i) {
        K k = K.a;
        if ((i & 4) != 0) {
            z = false;
        }
        g.F(k, k, z);
    }

    public static void O(G g) {
        com.quizlet.features.infra.basestudy.manager.f fVar = g.Z;
        fVar.g().o(com.quizlet.studiablemodels.assistantMode.a.b);
        fVar.g().p(assistantMode.enums.y.b);
        g.v1 = com.quizlet.featuregate.features.studymodes.learn.b.a;
        com.quizlet.features.infra.studysetting.managers.a aVarG = fVar.g();
        aVarG.getClass();
        aVarG.m(E1.GUIDANCE_DISABLED, true);
    }

    public final void D() {
        kotlinx.coroutines.E.A(p0.j(this), this.A1, null, new n(this, null), 2);
    }

    public final void E(com.google.firebase.crashlytics.internal.common.i iVar) {
        s0 s0Var;
        Object value;
        StudiableRoundProgress studiableRoundProgress;
        if (!P()) {
            kotlinx.coroutines.E.A(p0.j(this), null, null, new F(this, iVar, null), 3);
            return;
        }
        do {
            s0Var = this.J;
            value = s0Var.getValue();
            com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b bVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b) this.f.a;
            if (bVar.b()) {
                assistantMode.refactored.interfaces.a aVar = bVar.c;
                if (aVar == null) {
                    Intrinsics.m("studyEngine");
                    throw null;
                }
                assistantMode.refactored.c cVar = (assistantMode.refactored.c) aVar;
                if (cVar.e == null) {
                    cVar.a(System.currentTimeMillis(), K.a, false);
                }
                RoundProgress roundProgress = cVar.e;
                if (roundProgress == null) {
                    throw new IllegalStateException("mRoundProgress must not be null");
                }
                Intrinsics.checkNotNullParameter(roundProgress, "<this>");
                studiableRoundProgress = new StudiableRoundProgress(roundProgress.a, roundProgress.b);
            } else {
                studiableRoundProgress = null;
            }
        } while (!s0Var.k(value, new com.quizlet.learn.ui.toolbar.i(studiableRoundProgress)));
        if (iVar != null) {
            iVar.run();
        }
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    public final void F(List list, List list2, boolean z) {
        ArrayList arrayList = this.m1;
        arrayList.clear();
        ArrayList arrayList2 = this.n1;
        arrayList2.clear();
        if (this.k1 == null) {
            arrayList.addAll(list);
            arrayList2.addAll(list2);
            return;
        }
        this.p1.dispose();
        io.reactivex.rxjava3.core.i iVar = this.k1;
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = iVar != null ? new io.reactivex.rxjava3.internal.operators.flowable.b(new C4887f(iVar, 5), 2) : null;
        Intrinsics.d(bVar);
        io.reactivex.rxjava3.internal.observers.e eVarI = bVar.l(this.l).h(this.m).g(new com.quizlet.data.interactor.course.a(this, 16)).i(new p(this, list, list2, z), new l(this, 2));
        this.p1 = eVarI;
        Intrinsics.checkNotNullParameter(eVarI, "<this>");
        A(eVarI);
    }

    public final InterfaceC4176w0 H() {
        StudiableMeteringData studiableMeteringData;
        InterfaceC4176w0 interfaceC4176w0 = this.f1;
        if (!(interfaceC4176w0 instanceof C4179x0)) {
            return interfaceC4176w0;
        }
        C4179x0 c4179x0 = (C4179x0) interfaceC4176w0;
        StudiableStep studiableStep = this.l1;
        int i = (studiableStep == null || (studiableMeteringData = studiableStep.a) == null) ? ((C4179x0) interfaceC4176w0).a : studiableMeteringData.d;
        int i2 = c4179x0.b;
        P eventType = c4179x0.c;
        Long l = c4179x0.d;
        long j = c4179x0.e;
        S reason = c4179x0.f;
        c4179x0.getClass();
        Intrinsics.checkNotNullParameter(eventType, "eventType");
        Intrinsics.checkNotNullParameter(reason, "reason");
        return new C4179x0(i, i2, eventType, l, j, reason);
    }

    public final QuestionSettings I() {
        com.quizlet.features.infra.basestudy.manager.f fVar = this.Z;
        fVar.g().g = true;
        com.quizlet.features.infra.studysetting.managers.a aVarG = fVar.g();
        com.quizlet.features.infra.studysetting.data.c filter = this.c1 == 1 ? new retrofit2.adapter.rxjava3.d(27) : com.quizlet.features.infra.studysetting.data.b.a;
        aVarG.getClass();
        Intrinsics.checkNotNullParameter(filter, "filter");
        aVarG.a();
        QuestionSettings questionSettingsI = filter.i(aVarG.c(), aVarG);
        return !P() ? QuestionSettings.a(questionSettingsI, null, null, false, false, false, false, false, false, false, M().getDueDateTimestampMilliSec(), Long.valueOf(M().getStartTimestampMilliSec()), false, false, false, false, false, 260607) : questionSettingsI;
    }

    /* JADX WARN: Removed duplicated region for block: B:40:0x00f5  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00fc  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x015e  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x01b0 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:57:0x01b1 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object J(com.quizlet.learn.data.C4537b r36, java.util.List r37, java.util.List r38, com.quizlet.features.infra.studysetting.data.QuestionSettings r39, com.quizlet.generated.enums.A1 r40, boolean r41, kotlin.coroutines.jvm.internal.c r42) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 434
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.learn.viewmodel.G.J(com.quizlet.learn.data.b, java.util.List, java.util.List, com.quizlet.features.infra.studysetting.data.QuestionSettings, com.quizlet.generated.enums.A1, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final StudiableRoundProgress K() {
        com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b bVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b) this.f.a;
        if (!bVar.b()) {
            return null;
        }
        assistantMode.refactored.interfaces.a aVar = bVar.c;
        if (aVar == null) {
            Intrinsics.m("studyEngine");
            throw null;
        }
        assistantMode.refactored.interfaces.b bVar2 = ((assistantMode.refactored.c) aVar).b;
        if (!(bVar2 instanceof assistantMode.stepGenerators.b)) {
            throw new IllegalStateException(("TaskRoundProgress cannot be accessed using generator: " + bVar2).toString());
        }
        assistantMode.stepGenerators.types.b bVar3 = ((assistantMode.stepGenerators.b) bVar2).v;
        if (bVar3 == null) {
            throw new IllegalStateException("TaskStep must be generated before getting TaskRoundProgress");
        }
        Integer num = bVar3.d;
        Integer num2 = bVar3.f;
        TaskRoundProgress taskRoundProgress = num2.intValue() == 0 ? new TaskRoundProgress(1, 1) : new TaskRoundProgress(num.intValue(), num2.intValue());
        Intrinsics.checkNotNullParameter(taskRoundProgress, "<this>");
        return new StudiableRoundProgress(taskRoundProgress.a, taskRoundProgress.b);
    }

    public final StudiableTaskTotalProgress L() {
        com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b bVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b) this.f.a;
        if (!bVar.b()) {
            return null;
        }
        assistantMode.refactored.interfaces.a aVar = bVar.c;
        if (aVar == null) {
            Intrinsics.m("studyEngine");
            throw null;
        }
        assistantMode.refactored.interfaces.b bVar2 = ((assistantMode.refactored.c) aVar).b;
        if (bVar2 instanceof assistantMode.stepGenerators.b) {
            return new StudiableTaskTotalProgress(((assistantMode.stepGenerators.b) bVar2).g());
        }
        throw new IllegalStateException(("TaskSequenceProgress cannot be accessed using generator: " + bVar2).toString());
    }

    public final DBUserStudyable M() {
        com.quizlet.features.infra.basestudy.manager.f fVar = this.Z;
        List list = fVar.x.x;
        Intrinsics.checkNotNullExpressionValue(list, "getUserStudyables(...)");
        DBUserStudyable dBUserStudyable = (DBUserStudyable) CollectionsKt.firstOrNull(list);
        if (dBUserStudyable != null) {
            return dBUserStudyable;
        }
        long personId = this.i.getPersonId();
        int iB = fVar.v.b();
        this.v.getClass();
        DBUserStudyable dBUserStudyable2 = new DBUserStudyable(personId, fVar.u, iB, com.quizlet.time.b.a());
        this.e.a(dBUserStudyable2);
        return dBUserStudyable2;
    }

    public final void N(StudiableCheckpoint studiableCheckpoint, double d) {
        this.v.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        DBSession dBSession = this.j1;
        if (dBSession == null) {
            Intrinsics.m("session");
            throw null;
        }
        dBSession.setEndedTimestampMs(jCurrentTimeMillis);
        DBSession dBSession2 = this.j1;
        if (dBSession2 == null) {
            Intrinsics.m("session");
            throw null;
        }
        this.p.c(dBSession2);
        com.quizlet.features.infra.basestudy.manager.f fVar = this.Z;
        DBSession dBSessionB = fVar.b();
        this.j1 = dBSessionB;
        long id = dBSessionB.getId();
        com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a aVar = this.k;
        A1 a1 = fVar.o;
        aVar.a(id, a1);
        if (Intrinsics.b(this.x1, Boolean.TRUE)) {
            kotlinx.coroutines.E.A(p0.j(this), null, null, new t(this, studiableCheckpoint, true, null), 3);
            return;
        }
        boolean zP = P();
        Y y = this.L;
        StudyableModelData studyableModelData = fVar.l;
        if (zP) {
            y.j(new C4548m(studiableCheckpoint.b, d, fVar.d(), a1, studyableModelData));
            return;
        }
        C4549n c4549n = new C4549n(studyableModelData, this.f.b(), studiableCheckpoint.e, studiableCheckpoint.b);
        Integer numValueOf = Integer.valueOf(fVar.q);
        DBSession dBSession3 = fVar.x.C;
        long j = fVar.u;
        Long lValueOf = Long.valueOf(j);
        Long lValueOf2 = Long.valueOf(fVar.m);
        boolean z = fVar.k;
        com.quizlet.features.infra.basestudy.manager.c cVarC = fVar.r.c(j);
        this.q1.c(fVar.t, fVar.v, numValueOf, dBSession3, lValueOf, lValueOf2, z, "results", cVarC != null ? cVarC.a : null);
        y.j(c4549n);
    }

    public final boolean P() {
        return this.c1 == 1;
    }

    public final void Q() {
        io.reactivex.rxjava3.internal.operators.flowable.b bVar;
        com.quizlet.features.infra.basestudy.manager.f fVar = this.Z;
        if (fVar.x.d()) {
            bVar = io.reactivex.rxjava3.core.p.f(fVar.x);
        } else {
            io.reactivex.rxjava3.subjects.b bVarC = fVar.c();
            bVarC.getClass();
            bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new C4887f(bVarC, 5), 2);
        }
        io.reactivex.rxjava3.internal.operators.flowable.b bVar2 = bVar;
        io.reactivex.rxjava3.internal.observers.e eVarB = B7.b(bVar2, new com.quizlet.features.settings.composables.x(1, this, G.class, "onGenerateRoundError", "onGenerateRoundError(Ljava/lang/Throwable;)V", 0, 22), new com.quizlet.features.settings.composables.x(1, this, G.class, "onDataLoaded", "onDataLoaded(Lcom/quizlet/features/infra/basestudy/data/models/dataproviders/StudyModeDataProvider;)V", 0, 21));
        Intrinsics.checkNotNullParameter(eVarB, "<this>");
        A(eVarB);
        fVar.m();
        com.quizlet.features.infra.basestudy.manager.f.h(fVar);
    }

    public final void R(String str) {
        com.quizlet.features.infra.basestudy.manager.f fVar = this.Z;
        this.q1.f(fVar.t, fVar.v, Integer.valueOf(fVar.q), fVar.x.C, Long.valueOf(fVar.u), Long.valueOf(fVar.m), Boolean.valueOf(fVar.k), str);
    }

    public final void S() {
        StudiableTaskTotalProgress studiableTaskTotalProgressL;
        boolean zB = Intrinsics.b(this.x1, Boolean.TRUE);
        com.quizlet.learn.logging.a aVar = this.r;
        if (!zB || (studiableTaskTotalProgressL = L()) == null || studiableTaskTotalProgressL.a == 100.0d) {
            aVar.getClass();
            aVar.a(LearnEventLog.Companion.a(LearnEventLog.b, LearnEventAction.a, null, null, 30));
            this.L.j(C4544i.a);
            return;
        }
        com.quizlet.features.infra.basestudy.manager.f fVar = this.Z;
        String studySessionId = fVar.t;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        LearnEventLog.Companion companion = LearnEventLog.b;
        LearnEventAction learnEventAction = LearnEventAction.l;
        companion.getClass();
        aVar.a(LearnEventLog.Companion.b(learnEventAction, studySessionId));
        ArrayList arrayList = fVar.n;
        int size = arrayList != null ? arrayList.size() : 1;
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        com.quizlet.qutils.string.f fVar2 = new com.quizlet.qutils.string.f(R.string.are_you_sure_prompt, C4933y.P(args));
        Object[] args2 = {Integer.valueOf(size)};
        Intrinsics.checkNotNullParameter(args2, "args");
        com.quizlet.qutils.string.d dVar = new com.quizlet.qutils.string.d(R.plurals.focused_learn_exit_dialog_text, size, C4933y.P(args2));
        Object[] args3 = new Object[0];
        Intrinsics.checkNotNullParameter(args3, "args");
        com.quizlet.qutils.string.f fVar3 = new com.quizlet.qutils.string.f(R.string.exit_learn, C4933y.P(args3));
        Object[] args4 = new Object[0];
        Intrinsics.checkNotNullParameter(args4, "args");
        this.M.j(new L(fVar2, dVar, fVar3, new com.quizlet.qutils.string.f(R.string.cancel, C4933y.P(args4)), new j(this, studySessionId, 0), new j(this, studySessionId, 1)));
    }

    public final void T() {
        AdDataType adDataType;
        com.quizlet.learn.ads.h hVar = this.B1;
        if (!hVar.e && (adDataType = hVar.d) != null) {
            hVar.e = true;
            if (adDataType != null) {
                hVar.d = null;
                hVar.f.b(adDataType);
            }
        }
        if (((com.quizlet.learn.data.t) this.L.d()) instanceof C4546k) {
            R("checkpoint");
        }
        G(this, false, 7);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void U(Long l, boolean z) {
        LearnEventLog.LearnPayload learnPayload = null;
        Object[] objArr = 0;
        M().setStartTimestampSec(l != null ? Long.valueOf(l.longValue() / 1000) : null);
        com.quizlet.features.infra.basestudy.manager.f fVar = this.Z;
        long j = fVar.u;
        long personId = this.n.e.getPersonId();
        com.quizlet.learn.checkpoint.a aVar = this.h;
        aVar.getClass();
        aVar.a.edit().remove(d0.s(new Object[]{Long.valueOf(j), Long.valueOf(personId)}, 2, "review_all_terms_action_%s_set_id_person_id_%s", "format(...)")).apply();
        if (Intrinsics.b(this.x1, Boolean.TRUE) && z) {
            com.quizlet.learn.logging.c[] cVarArr = com.quizlet.learn.logging.c.a;
            com.quizlet.learn.logging.b[] bVarArr = com.quizlet.learn.logging.b.a;
            com.quizlet.features.infra.basestudy.manager.f.j(fVar, "study_all_terms", 4);
            this.M.j(com.quizlet.learn.data.K.a);
            return;
        }
        int i = 1;
        if (!P()) {
            com.quizlet.features.infra.studysetting.managers.a aVarG = fVar.g();
            aVarG.getClass();
            if ((com.quizlet.features.infra.studysetting.managers.a.d(aVarG, E1.GUIDANCE_DISABLED) || this.v1 == com.quizlet.featuregate.features.studymodes.learn.b.b) && !z) {
                com.quizlet.learn.logging.a aVar2 = this.r;
                aVar2.getClass();
                LearnEventLog.Companion companion = LearnEventLog.b;
                LearnEventAction restartAction = LearnEventAction.i;
                companion.getClass();
                Intrinsics.checkNotNullParameter(restartAction, "restartAction");
                LearnEventLog learnEventLog = new LearnEventLog(learnPayload, i, objArr == true ? 1 : 0);
                learnEventLog.setAction(restartAction.getValue());
                learnEventLog.setPayload(new LearnEventLog.LearnPayload.GoalAndProgressResetSelected(fVar.u));
                aVar2.a(learnEventLog);
                kotlinx.coroutines.E.A(p0.j(this), null, null, new z(this, null), 3);
                return;
            }
        }
        if (!z) {
            com.quizlet.features.infra.studysetting.managers.a aVarG2 = fVar.g();
            aVarG2.getClass();
            if (!com.quizlet.features.infra.studysetting.managers.a.d(aVarG2, E1.TASKS_ENABLED) && !P()) {
                com.quizlet.features.infra.studysetting.managers.a aVarG3 = fVar.g();
                C1 c1 = C1.STANDARD;
                aVarG3.getClass();
                if (c1 != null) {
                    aVarG3.n(E1.STUDY_PATH, c1.a());
                } else {
                    aVarG3.b(E1.STUDY_PATH);
                }
                fVar.g().o(com.quizlet.studiablemodels.assistantMode.a.b);
                fVar.g().p(assistantMode.enums.y.b);
            }
        }
        G(this, true, 3);
    }

    public final void V() {
        StudiableMeteringData meteringData;
        StudiableStep studiableStep = this.l1;
        if (studiableStep != null && (meteringData = studiableStep.a) != null) {
            com.quizlet.features.infra.basestudy.manager.f fVar = this.Z;
            long j = fVar.u;
            String studySessionId = fVar.t;
            StudyModeMeteringEventLogger studyModeMeteringEventLogger = this.w;
            studyModeMeteringEventLogger.getClass();
            Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
            Intrinsics.checkNotNullParameter(meteringData, "meteringData");
            int iOrdinal = meteringData.a.ordinal();
            studyModeMeteringEventLogger.b(j, meteringData, studySessionId, iOrdinal != 1 ? iOrdinal != 2 ? null : "test_remaining_attempts_toast_upgrade" : "learn_remaining_rounds_toast_upgrade");
        }
        this.M.j(com.quizlet.learn.data.G.a);
    }

    public final void W(LearnSettingsResult result) {
        Object i;
        Intrinsics.checkNotNullParameter(result, "result");
        if ((result instanceof LearnSettingsResult.Updated ? (LearnSettingsResult.Updated) result : null) != null) {
            com.quizlet.features.infra.basestudy.manager.f fVar = this.Z;
            LearnSettingsResult.Updated updated = (LearnSettingsResult.Updated) result;
            fVar.g().l(updated.a);
            if (updated.d) {
                O(this);
            }
            if (updated.b) {
                this.X.j(Boolean.valueOf(fVar.g().c().c));
            }
            if (updated.e) {
                this.u1 = true;
                DBSession dBSessionB = fVar.b();
                this.j1 = dBSessionB;
                this.k.a(dBSessionB.getId(), fVar.o);
                U(updated.a.k, false);
            }
            if (updated.c) {
                G(this, true, 3);
            }
            if (updated.f) {
                if (fVar.x.c()) {
                    i = new H(fVar.u, this.d1, this.e1, G1.SET, fVar.k, H());
                } else {
                    i = new I(fVar.u, this.d1, this.e1, G1.SET, fVar.k);
                }
                this.M.j(i);
            }
        }
    }

    public final void X() {
        io.reactivex.rxjava3.internal.operators.flowable.b bVar;
        if (((com.quizlet.learn.data.t) this.L.d()) instanceof C4549n) {
            R("results");
        }
        com.quizlet.features.infra.basestudy.manager.f fVar = this.Z;
        if (fVar.x.d()) {
            bVar = io.reactivex.rxjava3.core.p.f(fVar.x);
        } else {
            io.reactivex.rxjava3.subjects.b bVarC = fVar.c();
            bVarC.getClass();
            bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new C4887f(bVarC, 5), 2);
        }
        io.reactivex.rxjava3.internal.observers.e eVarB = B7.b(bVar, new com.quizlet.features.settings.composables.x(1, this, G.class, "onGenerateRoundError", "onGenerateRoundError(Ljava/lang/Throwable;)V", 0, 23), new com.quizlet.features.folders.composables.J(this, 21));
        Intrinsics.checkNotNullParameter(eVarB, "<this>");
        A(eVarB);
    }

    public final void Y(StudiableMeteringData studiableMeteringData) {
        Integer numValueOf = studiableMeteringData != null ? Integer.valueOf(studiableMeteringData.d) : null;
        Integer num = studiableMeteringData != null ? studiableMeteringData.c : null;
        com.quizlet.shared.enums.h hVar = studiableMeteringData != null ? studiableMeteringData.a : null;
        if (numValueOf == null || num == null || hVar == null) {
            return;
        }
        io.reactivex.rxjava3.internal.observers.e eVarI = this.q.q().i(new y(this, hVar, numValueOf, num, 0), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        Intrinsics.checkNotNullParameter(eVarI, "<this>");
        A(eVarI);
    }

    public final void Z(StudiableCheckpoint checkpoint) {
        Intrinsics.checkNotNullParameter(checkpoint, "checkpoint");
        this.e.c(Models.ANSWER);
        Y(checkpoint.e);
        boolean zP = P();
        com.quizlet.data.repository.progress.b bVar = this.f;
        if (zP) {
            StudiableTotalProgress studiableTotalProgressE = bVar.e();
            if (studiableTotalProgressE == null) {
                throw new IllegalArgumentException("Total progress must not be null");
            }
            double d = studiableTotalProgressE.b;
            if (d == 100.0d) {
                N(checkpoint, d);
            } else {
                com.quizlet.features.infra.basestudy.manager.f fVar = this.Z;
                this.L.j(new C4547l(checkpoint, studiableTotalProgressE, fVar.d(), fVar.o, fVar.l, this.d1));
            }
        } else {
            StudiableTaskTotalProgress studiableTaskTotalProgressL = L();
            if (studiableTaskTotalProgressL == null) {
                throw new IllegalArgumentException("Total progress must not be null");
            }
            if (studiableTaskTotalProgressL.a == 100.0d) {
                N(checkpoint, bVar.b() != null ? (r0.a * 100.0d) / r0.b : 100.0d);
            } else {
                kotlinx.coroutines.E.A(p0.j(this), null, null, new t(this, checkpoint, false, null), 3);
            }
        }
        kotlinx.coroutines.E.A(p0.j(this), null, null, new B(this, null), 3);
    }

    @Override // com.quizlet.viewmodel.a, com.quizlet.viewmodel.b, androidx.lifecycle.w0
    public final void z() {
        super.z();
        if (((com.quizlet.learn.data.t) this.L.d()) instanceof C4549n) {
            com.quizlet.features.infra.basestudy.manager.f fVar = this.Z;
            String str = fVar.t;
            Integer numValueOf = Integer.valueOf(fVar.q);
            DBSession dBSession = fVar.x.C;
            Long lValueOf = Long.valueOf(fVar.u);
            Long lValueOf2 = Long.valueOf(fVar.m);
            boolean z = fVar.k;
            this.q1.d(str, fVar.v, numValueOf, dBSession, lValueOf, lValueOf2, z, "results");
        }
        this.h1.g();
        this.i1.g();
        com.quizlet.data.repository.progress.b bVar = this.f;
        bVar.c = null;
        bVar.d = null;
        com.quizlet.learn.ads.h hVar = this.B1;
        ((io.reactivex.rxjava3.disposables.a) hVar.a.d.c.getValue()).dispose();
        CountDownTimer countDownTimer = (CountDownTimer) hVar.b.b;
        if (countDownTimer != null) {
            countDownTimer.cancel();
        }
        hVar.g.d();
    }
}
