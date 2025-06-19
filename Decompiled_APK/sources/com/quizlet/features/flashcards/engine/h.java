package com.quizlet.features.flashcards.engine;

import android.content.SharedPreferences;
import androidx.lifecycle.m0;
import assistantMode.enums.QuestionType$Companion;
import assistantMode.enums.m;
import assistantMode.refactored.types.FlashcardsMasteryBuckets;
import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.refactored.types.StudiableData;
import assistantMode.refactored.types.flashcards.FlashcardsCycleSummary;
import assistantMode.refactored.types.flashcards.FlashcardsModeProgress;
import assistantMode.refactored.types.flashcards.FlashcardsModeSettings;
import assistantMode.refactored.types.flashcards.FlashcardsQuestion;
import assistantMode.refactored.types.flashcards.FlashcardsRoundProgress;
import assistantMode.refactored.types.flashcards.FlashcardsRoundSummary;
import assistantMode.refactored.types.flashcards.FlashcardsSubmitAction;
import assistantMode.types.k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3146g0;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.google.android.gms.internal.mlkit_vision_barcode.E6;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_camera.L2;
import com.google.android.gms.internal.mlkit_vision_camera.T2;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.features.flashcards.data.t;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.E1;
import com.quizlet.generated.enums.G1;
import com.quizlet.generated.enums.O1;
import com.quizlet.infra.legacysyncengine.managers.i;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.StudiableDiagramImage;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.UUID;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class h {
    public final com.quizlet.data.interactor.achievements.f a;
    public final com.quizlet.data.repository.explanations.textbook.a b;
    public final com.quizlet.data.interactor.school.b c;
    public final com.quizlet.features.flashcards.logging.a d;
    public final i e;
    public final com.quizlet.features.flashcards.logging.b f;
    public final AbstractC5040y g;
    public boolean h;
    public com.quizlet.features.flashcards.data.e i;
    public com.quizlet.data.interactor.set.c j;
    public com.quizlet.features.infra.models.flashcards.d k;
    public final ArrayList l;
    public final ArrayList m;
    public final com.quizlet.features.infra.basestudy.manager.f n;
    public final long o;
    public final G1 p;
    public String q;
    public boolean r;
    public final s0 s;

    public h(m0 savedStateHandle, com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory, com.quizlet.data.interactor.achievements.f flashcardsSettingsHandler, com.quizlet.shared.usecase.folderstudymaterials.b flashcardsEngineFactory, com.quizlet.data.repository.explanations.textbook.a flashcardsModelManager, com.quizlet.data.interactor.school.b flashcardsResponseTracker, com.quizlet.features.flashcards.logging.a flashcardsEventLogger, i saveManager, com.quizlet.features.flashcards.logging.b flashcardsQuestionEventLogger, AbstractC5040y ioDispatcher) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        com.quizlet.features.infra.basestudy.utils.c studiableDataFactory = com.quizlet.features.infra.basestudy.utils.c.a;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        Intrinsics.checkNotNullParameter(flashcardsSettingsHandler, "flashcardsSettingsHandler");
        Intrinsics.checkNotNullParameter(flashcardsEngineFactory, "flashcardsEngineFactory");
        Intrinsics.checkNotNullParameter(flashcardsModelManager, "flashcardsModelManager");
        Intrinsics.checkNotNullParameter(flashcardsResponseTracker, "flashcardsResponseTracker");
        Intrinsics.checkNotNullParameter(flashcardsEventLogger, "flashcardsEventLogger");
        Intrinsics.checkNotNullParameter(saveManager, "saveManager");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        Intrinsics.checkNotNullParameter(studiableDataFactory, "studiableDataFactory");
        Intrinsics.checkNotNullParameter(flashcardsQuestionEventLogger, "flashcardsQuestionEventLogger");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = flashcardsSettingsHandler;
        this.b = flashcardsModelManager;
        this.c = flashcardsResponseTracker;
        this.d = flashcardsEventLogger;
        this.e = saveManager;
        this.f = flashcardsQuestionEventLogger;
        this.g = ioDispatcher;
        this.l = new ArrayList();
        this.m = new ArrayList();
        this.n = studyModeManagerFactory.a(savedStateHandle);
        Object objA = savedStateHandle.a("studyableModelData");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        StudyableModelData studyableModelData = (StudyableModelData) objA;
        this.o = studyableModelData.k();
        this.p = studyableModelData.getStudyableType();
        this.s = e0.c(null);
    }

    public static FlashcardsModeSettings m(com.quizlet.features.infra.models.flashcards.d dVar) {
        return new FlashcardsModeSettings(A.b(dVar.a), A.b(dVar.b), dVar.f ? com.quizlet.shared.enums.d.c : com.quizlet.shared.enums.d.b, dVar.b() == com.quizlet.features.infra.models.flashcards.c.c);
    }

    public static com.quizlet.features.flashcards.logging.c n(com.quizlet.features.flashcards.data.b bVar) {
        D6 front = bVar.c;
        Intrinsics.checkNotNullParameter(front, "front");
        D6 back = bVar.d;
        Intrinsics.checkNotNullParameter(back, "back");
        return new com.quizlet.features.flashcards.logging.c(bVar.b, front.e(), front.d(), front.c(), back.e(), back.d(), back.c());
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r14) {
        /*
            r13 = this;
            boolean r0 = r14 instanceof com.quizlet.features.flashcards.engine.a
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.features.flashcards.engine.a r0 = (com.quizlet.features.flashcards.engine.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.flashcards.engine.a r0 = new com.quizlet.features.flashcards.engine.a
            r0.<init>(r13, r14)
        L18:
            java.lang.Object r14 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L32
            if (r2 != r3) goto L2a
            com.quizlet.features.flashcards.engine.h r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto Lb0
        L2a:
            java.lang.IllegalStateException r14 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r14.<init>(r0)
            throw r14
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            com.quizlet.features.flashcards.data.e r14 = r13.i
            if (r14 == 0) goto L3c
            com.google.android.gms.internal.mlkit_vision_barcode.g0 r14 = r14.a
            goto L3d
        L3c:
            r14 = 0
        L3d:
            boolean r14 = r14 instanceof com.quizlet.features.flashcards.data.t
            if (r14 == 0) goto Lbf
            kotlinx.coroutines.flow.s0 r14 = r13.s
            java.lang.Object r14 = r14.getValue()
            com.quizlet.features.flashcards.data.e r14 = (com.quizlet.features.flashcards.data.e) r14
            if (r14 == 0) goto L91
            boolean r14 = r13.e()
            com.quizlet.features.flashcards.logging.a r2 = r13.d
            com.quizlet.eventlogger.features.flashcards.FlashcardsEventLog$Companion r4 = com.quizlet.eventlogger.features.flashcards.FlashcardsEventLog.b
            r4.getClass()
            java.lang.String r4 = "flashcards_next_action_button_clicked"
            java.lang.String r5 = "action"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r5)
            com.quizlet.eventlogger.features.flashcards.FlashcardsEventPayload r6 = new com.quizlet.eventlogger.features.flashcards.FlashcardsEventPayload
            r11 = 15
            r12 = 0
            r7 = 0
            r8 = 0
            r9 = 0
            r10 = 0
            r6.<init>(r7, r8, r9, r10, r11, r12)
            if (r14 == 0) goto L6e
            java.lang.String r14 = "QUIZ_MODE"
            goto L70
        L6e:
            java.lang.String r14 = "REVIEW_MODE"
        L70:
            r6.setSortingMode(r14)
            java.lang.String r14 = "$this$createEvent"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r14)
            java.lang.String r14 = "continue_flashcards"
            r6.setNextAction(r14)
            java.lang.String r14 = "checkpoint"
            r6.setScreenName(r14)
            kotlin.Unit r14 = kotlin.Unit.a
            com.quizlet.eventlogger.features.flashcards.FlashcardsEventLog r14 = new com.quizlet.eventlogger.features.flashcards.FlashcardsEventLog
            r14.<init>(r6)
            r14.setAction(r4)
            com.quizlet.eventlogger.EventLogger r2 = r2.a
            r2.l(r14)
        L91:
            com.quizlet.data.interactor.set.c r14 = r13.b()
            java.lang.Object r14 = r14.c
            assistantMode.refactored.studyEngines.b r14 = (assistantMode.refactored.studyEngines.b) r14
            androidx.camera.core.impl.i0 r14 = r14.n
            java.util.ArrayList r14 = r14.a
            java.util.List r2 = kotlin.collections.CollectionsKt.w0(r14)
            r14.clear()
            r0.j = r13
            r0.m = r3
            java.lang.Object r14 = r13.j(r2, r0)
            if (r14 != r1) goto Laf
            return r1
        Laf:
            r0 = r13
        Lb0:
            com.quizlet.data.interactor.set.c r14 = r0.b()
            assistantMode.refactored.types.flashcards.f r14 = r14.j()
            com.quizlet.features.flashcards.data.e r14 = r0.o(r14)
            r0.g(r14)
        Lbf:
            kotlin.Unit r14 = kotlin.Unit.a
            return r14
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.engine.h.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final com.quizlet.data.interactor.set.c b() {
        com.quizlet.data.interactor.set.c cVar = this.j;
        if (cVar != null) {
            return cVar;
        }
        throw new IllegalStateException("Engine not initialized");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final com.quizlet.features.infra.models.flashcards.d c() {
        com.quizlet.features.infra.basestudy.manager.f fVar = this.n;
        com.quizlet.features.infra.studysetting.managers.a studySettingManager = fVar.g();
        boolean z = fVar.k;
        ArrayList availableCardSides = fVar.x.z;
        Intrinsics.checkNotNullExpressionValue(availableCardSides, "getAvailableStudiableCardSideLabels(...)");
        com.quizlet.data.interactor.achievements.f fVar2 = this.a;
        Intrinsics.checkNotNullParameter(studySettingManager, "studySettingManager");
        Intrinsics.checkNotNullParameter(availableCardSides, "availableCardSides");
        G1 studyableModelType = this.p;
        Intrinsics.checkNotNullParameter(studyableModelType, "studyableModelType");
        com.quizlet.billing.register.a aVar = (com.quizlet.billing.register.a) fVar2.b;
        long j = this.o;
        com.quizlet.features.infra.basestudy.helper.b bVarA = aVar.a(j, studyableModelType);
        m mVar = m.b;
        m mVar2 = m.d;
        int iOrdinal = (availableCardSides.contains(mVar2) ? mVar2 : mVar).ordinal();
        int i = iOrdinal != 1 ? iOrdinal != 2 ? 0 : 2 : 1;
        m mVar3 = m.c;
        if (!availableCardSides.contains(mVar2) || !availableCardSides.contains(mVar)) {
            mVar = mVar3;
        }
        int iOrdinal2 = mVar.ordinal();
        int i2 = iOrdinal2 != 1 ? iOrdinal2 != 2 ? 0 : 2 : 1;
        com.quizlet.features.infra.basestudy.helper.b bVarA2 = aVar.a(j, studyableModelType);
        m frontSide = bVarA2.a;
        if (frontSide == null) {
            frontSide = com.quizlet.billing.register.a.b(i);
        }
        m backSide = bVarA2.b;
        if (backSide == null) {
            backSide = com.quizlet.billing.register.a.b(i2);
        }
        Long l = bVarA2.d;
        long jLongValue = l == null ? 0L : l.longValue();
        Boolean bool = bVarA2.c;
        com.quizlet.features.infra.models.flashcards.c cVar = (bool == null || !bool.booleanValue()) ? com.quizlet.features.infra.models.flashcards.c.d : com.quizlet.features.infra.models.flashcards.c.c;
        String strC = com.quizlet.billing.register.a.c(j, studyableModelType, "speakText");
        SharedPreferences sharedPreferences = aVar.a;
        boolean z2 = sharedPreferences.getBoolean(strC, false);
        boolean z3 = sharedPreferences.getBoolean(com.quizlet.billing.register.a.c(j, studyableModelType, "flashCardSpeakWord"), z2);
        boolean z4 = sharedPreferences.getBoolean(com.quizlet.billing.register.a.c(j, studyableModelType, "flashCardSpeakDefinition"), z2);
        boolean z5 = sharedPreferences.getBoolean(com.quizlet.billing.register.a.c(j, studyableModelType, "flashCardPlay"), false);
        boolean z6 = sharedPreferences.getBoolean(com.quizlet.billing.register.a.c(j, studyableModelType, "flashCardShuffle"), true);
        Intrinsics.checkNotNullParameter(frontSide, "frontSide");
        Intrinsics.checkNotNullParameter(backSide, "backSide");
        Long l2 = bVarA.d;
        if (l2 != null) {
            long jLongValue2 = l2.longValue();
            studySettingManager.getClass();
            studySettingManager.n(E1.CARDS_SHUFFLE_RANDOM_SEED, jLongValue2);
        }
        m mVar4 = bVarA.a;
        if (mVar4 != null) {
            studySettingManager.getClass();
            studySettingManager.n(E1.CARDS_PROMPT_SIDES, M6.a(A.b(AbstractC3106b5.g(mVar4))));
        }
        m mVar5 = bVarA.b;
        if (mVar5 != null) {
            studySettingManager.getClass();
            studySettingManager.n(E1.CARDS_ANSWER_SIDES, M6.a(A.b(AbstractC3106b5.g(mVar5))));
        }
        studySettingManager.getClass();
        long jE = studySettingManager.e(E1.CARDS_SHUFFLE_RANDOM_SEED, 0L);
        Boolean bool2 = bVarA.c;
        boolean zBooleanValue = bool2 != null ? bool2.booleanValue() : com.quizlet.features.infra.studysetting.managers.a.d(studySettingManager, E1.CARDS_SORTING_ON);
        studySettingManager.m(E1.CARDS_SORTING_ON, zBooleanValue);
        O1 o1 = (O1) CollectionsKt.firstOrNull(M6.d(studySettingManager.e(E1.CARDS_PROMPT_SIDES, null)));
        m mVarF = o1 != null ? AbstractC3106b5.f(o1) : null;
        if (mVarF == null) {
            mVarF = frontSide;
        }
        O1 o12 = (O1) CollectionsKt.firstOrNull(M6.d(studySettingManager.e(E1.CARDS_ANSWER_SIDES, null)));
        m mVarF2 = o12 != null ? AbstractC3106b5.f(o12) : null;
        if (mVarF2 == null) {
            mVarF2 = backSide;
        }
        int i3 = !zBooleanValue;
        boolean z7 = jE > 0;
        if ((92 & 1) == 0) {
            frontSide = mVarF;
        }
        if ((92 & 2) == 0) {
            backSide = mVarF2;
        }
        boolean z8 = (92 & 16) != 0 ? z5 : false;
        if ((92 & 32) == 0) {
            z6 = z7;
        }
        if ((92 & 128) == 0) {
            jLongValue = jE;
        }
        if ((92 & 256) != 0) {
            i3 = cVar.a;
        }
        Intrinsics.checkNotNullParameter(frontSide, "frontSide");
        Intrinsics.checkNotNullParameter(backSide, "backSide");
        return new com.quizlet.features.infra.models.flashcards.d(frontSide, backSide, z3, z4, z8, z6, z, jLongValue, i3);
    }

    public final com.quizlet.features.infra.models.flashcards.d d() {
        if (this.k == null) {
            this.k = c();
        }
        com.quizlet.features.infra.models.flashcards.d dVar = this.k;
        if (dVar != null) {
            return dVar;
        }
        Intrinsics.m("_settings");
        throw null;
    }

    public final boolean e() {
        return d().b() == com.quizlet.features.infra.models.flashcards.c.c;
    }

    public final void f(com.quizlet.features.infra.models.flashcards.h hVar) {
        com.quizlet.features.flashcards.data.e eVar = this.i;
        Object obj = eVar != null ? eVar.a : null;
        com.quizlet.features.flashcards.data.b bVar = obj instanceof com.quizlet.features.flashcards.data.b ? (com.quizlet.features.flashcards.data.b) obj : null;
        if (bVar == null) {
            return;
        }
        String studySessionId = this.n.t;
        if (this.q == null) {
            this.q = UUID.randomUUID().toString();
        }
        String questionSessionId = this.q;
        Intrinsics.d(questionSessionId);
        com.quizlet.features.flashcards.logging.c questionLoggingData = n(bVar);
        m frontSide = d().a;
        m revealSide = E6.f(hVar, d());
        com.quizlet.features.flashcards.logging.b bVar2 = this.f;
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
        Intrinsics.checkNotNullParameter(questionLoggingData, "questionLoggingData");
        Intrinsics.checkNotNullParameter(frontSide, "frontSide");
        Intrinsics.checkNotNullParameter(revealSide, "revealSide");
        bVar2.a.v(com.quizlet.features.flashcards.logging.b.a(studySessionId, questionSessionId, "view_end", questionLoggingData, frontSide, revealSide, null, null, null));
    }

    public final void g(com.quizlet.features.flashcards.data.e eVar) {
        s0 s0Var;
        Object value;
        AbstractC3146g0 abstractC3146g0 = eVar.a;
        if (abstractC3146g0 instanceof t) {
            t tVar = (t) abstractC3146g0;
            com.quizlet.features.infra.basestudy.manager.f.k(this.n, tVar.d > 0 ? "checkpoint" : "results", Boolean.valueOf(e()), 2);
            if (!(tVar instanceof t)) {
                throw new NoWhenBranchMatchedException();
            }
            com.quizlet.features.flashcards.logging.a aVar = this.d;
            AndroidEventLog androidEventLogB = AndroidEventLog.Companion.b(AndroidEventLog.b, "user_action_flashcards", null, 14);
            androidEventLogB.setUserActionFlashcards("flashcard_response_completed_round");
            androidEventLogB.setFlashcardsNumRoundsCompleted(Integer.valueOf(tVar.e));
            androidEventLogB.setFlashcardsPctSwipedOutOfStack(Integer.valueOf((int) ((eVar.d / eVar.b) * 100)));
            aVar.a.v(androidEventLogB);
        }
        this.i = eVar;
        do {
            s0Var = this.s;
            value = s0Var.getValue();
        } while (!s0Var.k(value, eVar));
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x006f, code lost:
    
        if (r6 == r1) goto L25;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object h(kotlin.coroutines.jvm.internal.c r6) throws java.lang.Throwable {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.features.flashcards.engine.c
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.features.flashcards.engine.c r0 = (com.quizlet.features.flashcards.engine.c) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.flashcards.engine.c r0 = new com.quizlet.features.flashcards.engine.c
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L72
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L32:
            com.quizlet.features.flashcards.engine.h r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L50
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.features.infra.basestudy.manager.f r6 = r5.n
            r6.m()
            io.reactivex.rxjava3.subjects.b r6 = r6.c()
            r0.j = r5
            r0.m = r4
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.I1.c(r6, r0)
            if (r6 != r1) goto L4f
            goto L71
        L4f:
            r2 = r5
        L50:
            java.lang.String r4 = "awaitFirst(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r4)
            com.quizlet.features.infra.basestudy.data.models.dataproviders.a r6 = (com.quizlet.features.infra.basestudy.data.models.dataproviders.a) r6
            r4 = 0
            r0.j = r4
            r0.m = r3
            r2.getClass()
            com.quizlet.features.flashcards.engine.b r3 = new com.quizlet.features.flashcards.engine.b
            r3.<init>(r2, r6, r4)
            kotlinx.coroutines.y r6 = r2.g
            java.lang.Object r6 = kotlinx.coroutines.E.J(r6, r3, r0)
            if (r6 != r1) goto L6d
            goto L6f
        L6d:
            kotlin.Unit r6 = kotlin.Unit.a
        L6f:
            if (r6 != r1) goto L72
        L71:
            return r1
        L72:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.engine.h.h(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0015  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object i(kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            r9 = this;
            r0 = 0
            r1 = 1
            boolean r2 = r10 instanceof com.quizlet.features.flashcards.engine.d
            if (r2 == 0) goto L15
            r2 = r10
            com.quizlet.features.flashcards.engine.d r2 = (com.quizlet.features.flashcards.engine.d) r2
            int r3 = r2.m
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L15
            int r3 = r3 - r4
            r2.m = r3
            goto L1a
        L15:
            com.quizlet.features.flashcards.engine.d r2 = new com.quizlet.features.flashcards.engine.d
            r2.<init>(r9, r10)
        L1a:
            java.lang.Object r10 = r2.k
            kotlin.coroutines.intrinsics.a r3 = kotlin.coroutines.intrinsics.a.a
            int r4 = r2.m
            if (r4 == 0) goto L33
            if (r4 != r1) goto L2b
            com.quizlet.features.flashcards.engine.h r0 = r2.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto Lab
        L2b:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            com.quizlet.features.infra.basestudy.manager.f r10 = r9.n
            com.quizlet.features.infra.basestudy.data.models.dataproviders.a r4 = r10.x
            com.quizlet.db.data.models.persisted.DBSession r4 = r4.C
            if (r4 == 0) goto L4e
            long r5 = java.lang.System.currentTimeMillis()
            r4.setEndedTimestampMs(r5)
            com.quizlet.infra.legacysyncengine.managers.i r5 = r9.e
            com.quizlet.db.data.models.base.DBModel[] r6 = new com.quizlet.db.data.models.base.DBModel[r1]
            r6[r0] = r4
            r5.c(r6)
        L4e:
            com.quizlet.ads.d r4 = r10.j
            if (r4 == 0) goto L84
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            java.lang.String r6 = "RateUsPromoSessionCount_"
            r5.<init>(r6)
            long r7 = r4.a
            r5.append(r7)
            java.lang.String r5 = r5.toString()
            android.content.SharedPreferences r4 = r4.b
            int r0 = r4.getInt(r5, r0)
            int r0 = r0 + r1
            r5 = 3
            if (r0 <= r5) goto L6d
            goto L84
        L6d:
            android.content.SharedPreferences$Editor r4 = r4.edit()
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            r5.<init>(r6)
            r5.append(r7)
            java.lang.String r5 = r5.toString()
            android.content.SharedPreferences$Editor r0 = r4.putInt(r5, r0)
            r0.apply()
        L84:
            r10.b()
            r2.j = r9
            r2.m = r1
            com.quizlet.data.interactor.set.c r10 = r9.b()
            java.lang.Object r10 = r10.c
            assistantMode.refactored.studyEngines.b r10 = (assistantMode.refactored.studyEngines.b) r10
            androidx.camera.core.impl.i0 r10 = r10.n
            java.util.ArrayList r10 = r10.a
            java.util.List r0 = kotlin.collections.CollectionsKt.w0(r10)
            r10.clear()
            java.lang.Object r10 = r9.j(r0, r2)
            if (r10 != r3) goto La5
            goto La7
        La5:
            kotlin.Unit r10 = kotlin.Unit.a
        La7:
            if (r10 != r3) goto Laa
            return r3
        Laa:
            r0 = r9
        Lab:
            com.quizlet.data.interactor.set.c r10 = r0.b()
            kotlin.random.d r2 = kotlin.random.e.a
            r2.getClass()
            kotlin.random.a r2 = kotlin.random.e.b
            int r2 = r2.c()
            int r2 = java.lang.Math.abs(r2)
            int r2 = java.lang.Math.max(r2, r1)
            java.lang.Object r3 = r10.c
            assistantMode.refactored.studyEngines.b r3 = (assistantMode.refactored.studyEngines.b) r3
            kotlin.random.g r4 = new kotlin.random.g
            int r5 = r2 >> 31
            r4.<init>(r2, r5)
            r2 = 5
            r5 = 0
            assistantMode.refactored.studyEngines.b r2 = assistantMode.refactored.studyEngines.b.d(r3, r5, r4, r5, r2)
            r10.c = r2
            r2.l = r1
            assistantMode.refactored.types.flashcards.f r10 = r2.b()
            com.quizlet.features.flashcards.data.e r10 = r0.o(r10)
            r0.g(r10)
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.engine.h.i(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final Object j(List list, kotlin.coroutines.jvm.internal.c cVar) throws Throwable {
        Object objJ = E.J(this.g, new e(this, list, null), cVar);
        return objJ == kotlin.coroutines.intrinsics.a.a ? objJ : Unit.a;
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0049, code lost:
    
        if (h(r0) == r1) goto L24;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object k(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.features.flashcards.engine.g
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.features.flashcards.engine.g r0 = (com.quizlet.features.flashcards.engine.g) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.flashcards.engine.g r0 = new com.quizlet.features.flashcards.engine.g
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L34
            if (r2 != r3) goto L2c
            com.quizlet.features.flashcards.engine.h r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L6c
        L2c:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L34:
            com.quizlet.features.flashcards.engine.h r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4d
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.data.interactor.set.c r6 = r5.j
            if (r6 != 0) goto L4c
            r0.j = r5
            r0.m = r4
            java.lang.Object r6 = r5.h(r0)
            if (r6 != r1) goto L4c
            goto L6a
        L4c:
            r2 = r5
        L4d:
            com.quizlet.data.interactor.set.c r6 = r2.b()
            java.lang.Object r6 = r6.c
            assistantMode.refactored.studyEngines.b r6 = (assistantMode.refactored.studyEngines.b) r6
            androidx.camera.core.impl.i0 r6 = r6.n
            java.util.ArrayList r6 = r6.a
            java.util.List r4 = kotlin.collections.CollectionsKt.w0(r6)
            r6.clear()
            r0.j = r2
            r0.m = r3
            java.lang.Object r6 = r2.j(r4, r0)
            if (r6 != r1) goto L6b
        L6a:
            return r1
        L6b:
            r0 = r2
        L6c:
            com.quizlet.data.interactor.set.c r6 = r0.b()
            assistantMode.refactored.types.flashcards.f r6 = r6.j()
            com.quizlet.features.flashcards.data.e r6 = r0.o(r6)
            r0.g(r6)
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.engine.h.k(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x0055  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0079  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0081  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0132  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x01e1  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void l(assistantMode.enums.EnumC1448b r22, com.quizlet.features.infra.models.flashcards.h r23) {
        /*
            Method dump skipped, instructions count: 489
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.engine.h.l(assistantMode.enums.b, com.quizlet.features.infra.models.flashcards.h):void");
    }

    public final com.quizlet.features.flashcards.data.e o(assistantMode.refactored.types.flashcards.f fVar) {
        AbstractC3146g0 tVar;
        DBSelectedTerm dBSelectedTerm;
        if (fVar instanceof FlashcardsQuestion) {
            FlashcardsQuestion flashcardsQuestion = (FlashcardsQuestion) fVar;
            FlashcardsRoundProgress flashcardsRoundProgress = flashcardsQuestion.c.f;
            com.quizlet.features.infra.models.flashcards.h hVar = com.quizlet.features.infra.models.flashcards.h.a;
            RevealSelfAssessmentQuestion revealSelfAssessmentQuestion = flashcardsQuestion.a;
            Long l = revealSelfAssessmentQuestion.d.a;
            long jLongValue = l != null ? l.longValue() : 0L;
            k kVar = (k) CollectionsKt.firstOrNull(this.m);
            StudiableDiagramImage studiableDiagramImageB = kVar != null ? com.quizlet.studiablemodels.grading.c.b(kVar) : null;
            ArrayList arrayListD = com.quizlet.features.infra.basestudy.utils.b.d(this.l);
            QuestionSectionData questionSectionDataC = com.quizlet.studiablemodels.grading.c.c(revealSelfAssessmentQuestion.a, arrayListD);
            QuestionSectionData questionSectionDataC2 = com.quizlet.studiablemodels.grading.c.c(revealSelfAssessmentQuestion.b, arrayListD);
            D6 front = com.quizlet.features.infra.basestudy.helper.a.a(questionSectionDataC, studiableDiagramImageB);
            D6 back = com.quizlet.features.infra.basestudy.helper.a.a(questionSectionDataC2, studiableDiagramImageB);
            boolean zE = e();
            com.quizlet.features.infra.basestudy.manager.f fVar2 = this.n;
            com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = fVar2.x;
            boolean z = (!aVar.d() || (dBSelectedTerm = (DBSelectedTerm) aVar.B.c(jLongValue)) == null || dBSelectedTerm.getDeleted()) ? false : true;
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            AbstractC3146g0 bVar = new com.quizlet.features.flashcards.data.b(jLongValue, front, back, zE, z, hVar, new com.quizlet.qutils.string.f(R.string.flashcards_still_learning, C4933y.P(args)));
            Intrinsics.checkNotNullParameter(front, "front");
            Intrinsics.checkNotNullParameter(back, "back");
            com.quizlet.features.flashcards.logging.c questionLoggingData = new com.quizlet.features.flashcards.logging.c(jLongValue, front.e(), front.d(), front.c(), back.e(), back.d(), back.c());
            String questionSessionId = UUID.randomUUID().toString();
            this.q = questionSessionId;
            Intrinsics.d(questionSessionId);
            m frontSide = d().a;
            m revealSide = d().b;
            com.quizlet.features.flashcards.logging.b bVar2 = this.f;
            String studySessionId = fVar2.t;
            Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
            Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
            Intrinsics.checkNotNullParameter(questionLoggingData, "questionLoggingData");
            Intrinsics.checkNotNullParameter(frontSide, "frontSide");
            Intrinsics.checkNotNullParameter(revealSide, "revealSide");
            bVar2.a.v(com.quizlet.features.flashcards.logging.b.a(studySessionId, questionSessionId, "view_start", questionLoggingData, frontSide, revealSide, null, A1.FLASHCARDS, assistantMode.enums.k.f));
            if (!this.r) {
                this.r = true;
                boolean z2 = d().a == m.b;
                boolean z3 = d().a == m.c;
                int i = flashcardsRoundProgress.c + flashcardsRoundProgress.e;
                com.quizlet.features.flashcards.logging.a aVar2 = this.d;
                int i2 = flashcardsRoundProgress.g;
                if ((z2 && d().c) || (z3 && d().d)) {
                    com.quizlet.features.flashcards.logging.a.a(aVar2, "show_first_card_audio", Integer.valueOf(i), Integer.valueOf(i2), null, 56);
                } else {
                    com.quizlet.features.flashcards.logging.a.a(aVar2, "show_first_card", Integer.valueOf(i), Integer.valueOf(i2), null, 56);
                }
            }
            tVar = bVar;
        } else {
            if (!(fVar instanceof FlashcardsCycleSummary)) {
                if (fVar instanceof FlashcardsRoundSummary) {
                    throw new IllegalStateException("No longer support Round screens");
                }
                throw new NoWhenBranchMatchedException();
            }
            FlashcardsModeProgress flashcardsModeProgress = ((FlashcardsCycleSummary) fVar).b;
            FlashcardsRoundProgress flashcardsRoundProgress2 = flashcardsModeProgress.f;
            this.h = true;
            tVar = new t(e(), flashcardsRoundProgress2.c, flashcardsRoundProgress2.e, flashcardsModeProgress.b);
        }
        FlashcardsRoundProgress flashcardsRoundProgress3 = fVar.a().f;
        assistantMode.refactored.types.c cVar = fVar.a().a.a;
        Intrinsics.e(cVar, "null cannot be cast to non-null type assistantMode.refactored.types.FlashcardsMasteryBuckets");
        FlashcardsMasteryBuckets flashcardsMasteryBuckets = (FlashcardsMasteryBuckets) cVar;
        List list = flashcardsMasteryBuckets.a;
        int size = list.size();
        int i3 = flashcardsRoundProgress3.d;
        return new com.quizlet.features.flashcards.data.e(tVar, size + i3, flashcardsRoundProgress3.f, i3, flashcardsMasteryBuckets.b.size() + list.size(), !((assistantMode.refactored.studyEngines.b) b().c).m.isEmpty());
    }

    public final void p(com.quizlet.features.infra.models.flashcards.d settings) {
        com.quizlet.features.infra.basestudy.manager.f fVar = this.n;
        com.quizlet.features.infra.studysetting.managers.a studySettingManager = fVar.g();
        com.quizlet.data.interactor.achievements.f fVar2 = this.a;
        Intrinsics.checkNotNullParameter(studySettingManager, "studySettingManager");
        Intrinsics.checkNotNullParameter(settings, "settings");
        G1 studyableModelType = this.p;
        Intrinsics.checkNotNullParameter(studyableModelType, "studyableModelType");
        long j = settings.h;
        studySettingManager.getClass();
        studySettingManager.n(E1.CARDS_SHUFFLE_RANDOM_SEED, j);
        m mVar = settings.a;
        studySettingManager.n(E1.CARDS_PROMPT_SIDES, mVar != null ? M6.a(A.b(AbstractC3106b5.g(mVar))) : 0L);
        m mVar2 = settings.b;
        studySettingManager.n(E1.CARDS_ANSWER_SIDES, mVar2 != null ? M6.a(A.b(AbstractC3106b5.g(mVar2))) : 0L);
        studySettingManager.m(E1.CARDS_SORTING_ON, settings.b() == com.quizlet.features.infra.models.flashcards.c.c);
        ((com.quizlet.billing.register.a) fVar2.b).e(this.o, studyableModelType, settings);
        fVar.k = settings.g;
        this.k = settings;
    }

    public final void q(com.quizlet.features.infra.models.flashcards.d settings) {
        Intrinsics.checkNotNullParameter(settings, "settings");
        p(settings);
        com.quizlet.data.interactor.set.c cVarB = b();
        FlashcardsModeSettings settings2 = m(settings);
        Intrinsics.checkNotNullParameter(settings2, "settings");
        QuestionType$Companion questionType$Companion = assistantMode.enums.k.Companion;
        ArrayList updatedFlashcards = L2.b((StudiableData) cVarB.a, settings2.a, settings2.b);
        List list = ((assistantMode.refactored.studyEngines.b) cVarB.c).g;
        Intrinsics.checkNotNullParameter(list, "<this>");
        Intrinsics.checkNotNullParameter(updatedFlashcards, "other");
        if (Intrinsics.b(CollectionsKt.A0(T2.f(list)), CollectionsKt.A0(T2.f(updatedFlashcards)))) {
            assistantMode.refactored.studyEngines.b bVar = (assistantMode.refactored.studyEngines.b) cVarB.c;
            bVar.getClass();
            Intrinsics.checkNotNullParameter(updatedFlashcards, "updatedFlashcards");
            bVar.g = updatedFlashcards;
            Intrinsics.checkNotNullParameter(updatedFlashcards, "<this>");
            int iA = U.a(C.q(updatedFlashcards, 10));
            if (iA < 16) {
                iA = 16;
            }
            LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
            Iterator it2 = updatedFlashcards.iterator();
            while (it2.hasNext()) {
                RevealSelfAssessmentQuestion revealSelfAssessmentQuestion = (RevealSelfAssessmentQuestion) it2.next();
                Long l = revealSelfAssessmentQuestion.d.a;
                Intrinsics.d(l);
                linkedHashMap.put(l, revealSelfAssessmentQuestion);
            }
            T2.d(linkedHashMap, bVar.c);
            T2.d(linkedHashMap, bVar.f);
            T2.d(linkedHashMap, bVar.d);
            T2.d(linkedHashMap, bVar.e);
            ListIterator listIterator = bVar.m.listIterator();
            while (listIterator.hasNext()) {
                Pair pair = (Pair) listIterator.next();
                RevealSelfAssessmentQuestion revealSelfAssessmentQuestion2 = (RevealSelfAssessmentQuestion) linkedHashMap.get(((FlashcardsSubmitAction) pair.b).a.d.a);
                if (revealSelfAssessmentQuestion2 != null) {
                    FlashcardsSubmitAction flashcardsSubmitAction = (FlashcardsSubmitAction) pair.b;
                    listIterator.set(new Pair(pair.a, new FlashcardsSubmitAction(revealSelfAssessmentQuestion2, flashcardsSubmitAction.b, flashcardsSubmitAction.c)));
                }
            }
        } else {
            assistantMode.refactored.studyEngines.b bVarD = assistantMode.refactored.studyEngines.b.d((assistantMode.refactored.studyEngines.b) cVarB.c, settings2, null, updatedFlashcards, 2);
            cVarB.c = bVarD;
            bVarD.l = true;
        }
        assistantMode.refactored.studyEngines.b bVar2 = (assistantMode.refactored.studyEngines.b) cVarB.c;
        bVar2.getClass();
        Intrinsics.checkNotNullParameter(settings2, "settings");
        com.quizlet.shared.enums.d dVar = bVar2.b.c;
        com.quizlet.shared.enums.d dVar2 = settings2.c;
        boolean z = dVar != dVar2;
        bVar2.b = settings2;
        if (z) {
            int iOrdinal = dVar2.ordinal();
            ArrayList arrayList = bVar2.d;
            List list2 = bVar2.e;
            if (iOrdinal == 0) {
                List list3 = bVar2.a.a;
                ArrayList arrayList2 = new ArrayList(C.q(list3, 10));
                Iterator it3 = list3.iterator();
                while (it3.hasNext()) {
                    arrayList2.add(Long.valueOf(((assistantMode.refactored.modelTypes.d) it3.next()).getId()));
                }
                T2.e(arrayList2, arrayList);
                T2.e(arrayList2, list2);
            } else if (iOrdinal == 1) {
                kotlin.random.e eVar = bVar2.j;
                CollectionsKt.h0(arrayList, eVar);
                CollectionsKt.h0(list2, eVar);
            }
            bVar2.m.clear();
        }
        g(o(((assistantMode.refactored.studyEngines.b) cVarB.c).b()));
    }
}
