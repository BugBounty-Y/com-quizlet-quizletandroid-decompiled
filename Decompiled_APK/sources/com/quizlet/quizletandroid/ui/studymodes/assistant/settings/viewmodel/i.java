package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.work.impl.model.l;
import assistantMode.enums.y;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.G2;
import com.google.android.gms.internal.mlkit_vision_camera.j3;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.learn.LearnEventAction;
import com.quizlet.eventlogger.features.learn.LearnEventLog;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.eventlogger.features.writetransition.WriteTransitionEventAction;
import com.quizlet.eventlogger.features.writetransition.WriteTransitionEventLog;
import com.quizlet.eventlogger.features.writetransition.WriteTransitionPayload;
import com.quizlet.eventlogger.features.writetransition.WriteTransitionScreenName;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.E1;
import com.quizlet.generated.enums.G1;
import com.quizlet.learn.settings.data.LearnSettingsResult;
import com.quizlet.quizletandroid.ui.login.z;
import com.quizlet.quizletandroid.ui.setcreation.managers.n;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUpdateData;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.j;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.o;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class i extends w0 implements a {
    public final m0 b;
    public final com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.d c;
    public final l d;
    public final com.quizlet.learn.logging.a e;
    public final n f;
    public final com.quizlet.login.common.interactors.d g;
    public final com.quizlet.login.authentication.login.a h;
    public final com.quizlet.data.interactor.achievements.f i;
    public final com.google.firebase.crashlytics.internal.settings.b j;
    public final com.quizlet.features.setpage.logging.writetransition.a k;
    public final com.quizlet.data.repository.user.a l;
    public final AbstractC5040y m;
    public final com.quizlet.infra.legacysyncengine.features.properties.d n;
    public final com.quizlet.learn.usecase.d o;
    public final s0 p;
    public final d0 q;
    public final com.quizlet.features.infra.basestudy.manager.f r;
    public final StudyModeEventLogger s;

    public i(com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory, StudyModeEventLogger.Factory studyModeEventLoggerFactory, m0 savedStateHandle, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.d saveLearnSettingsUseCase, l restartLearnUseCase, com.quizlet.learn.logging.a learnEventLogger, n getLearnSettingsGuidanceEnabledUseCase, com.quizlet.login.common.interactors.d updateLearnGuidanceUseCase, com.quizlet.login.authentication.login.a getLearnPlusTasksEnabledUseCase, com.quizlet.data.interactor.achievements.f getSettingsTermValueUseCase, com.google.firebase.crashlytics.internal.settings.b getSettingsDefinitionValueUseCase, com.quizlet.features.setpage.logging.writetransition.a writeTransitionFeatureLogger, com.quizlet.data.repository.user.a improveSmartGradingFeature, AbstractC5040y ioDispatcher, com.quizlet.infra.legacysyncengine.features.properties.d studySetProperties, com.quizlet.learn.usecase.d getWrittenGradingOptionsUseCase) {
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        Intrinsics.checkNotNullParameter(studyModeEventLoggerFactory, "studyModeEventLoggerFactory");
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(saveLearnSettingsUseCase, "saveLearnSettingsUseCase");
        Intrinsics.checkNotNullParameter(restartLearnUseCase, "restartLearnUseCase");
        Intrinsics.checkNotNullParameter(learnEventLogger, "learnEventLogger");
        Intrinsics.checkNotNullParameter(getLearnSettingsGuidanceEnabledUseCase, "getLearnSettingsGuidanceEnabledUseCase");
        Intrinsics.checkNotNullParameter(updateLearnGuidanceUseCase, "updateLearnGuidanceUseCase");
        Intrinsics.checkNotNullParameter(getLearnPlusTasksEnabledUseCase, "getLearnPlusTasksEnabledUseCase");
        Intrinsics.checkNotNullParameter(getSettingsTermValueUseCase, "getSettingsTermValueUseCase");
        Intrinsics.checkNotNullParameter(getSettingsDefinitionValueUseCase, "getSettingsDefinitionValueUseCase");
        Intrinsics.checkNotNullParameter(writeTransitionFeatureLogger, "writeTransitionFeatureLogger");
        Intrinsics.checkNotNullParameter(improveSmartGradingFeature, "improveSmartGradingFeature");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        Intrinsics.checkNotNullParameter(studySetProperties, "studySetProperties");
        Intrinsics.checkNotNullParameter(getWrittenGradingOptionsUseCase, "getWrittenGradingOptionsUseCase");
        this.b = savedStateHandle;
        this.c = saveLearnSettingsUseCase;
        this.d = restartLearnUseCase;
        this.e = learnEventLogger;
        this.f = getLearnSettingsGuidanceEnabledUseCase;
        this.g = updateLearnGuidanceUseCase;
        this.h = getLearnPlusTasksEnabledUseCase;
        this.i = getSettingsTermValueUseCase;
        this.j = getSettingsDefinitionValueUseCase;
        this.k = writeTransitionFeatureLogger;
        this.l = improveSmartGradingFeature;
        this.m = ioDispatcher;
        this.n = studySetProperties;
        this.o = getWrittenGradingOptionsUseCase;
        this.p = e0.c(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.n.a);
        this.q = e0.b(0, 1, null, 5);
        this.r = studyModeManagerFactory.a(savedStateHandle);
        this.s = studyModeEventLoggerFactory.a(A1.LEARNING_ASSISTANT);
        E.A(p0.j(this), null, null, new b(this, null), 3);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:21:0x014c  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x014f  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0199  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x019b  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x01a8  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x01ad  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x01b5  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x01ba  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0222  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0240  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0243  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x024e  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0251  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0257  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x025a  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0260  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0263  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0269  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x026c  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0272  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x0275  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x027b  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x027e  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x0286  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0289  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x028f  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0292  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0298  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x029b  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001a  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x02a1  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x02ac  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x02b4  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x02be  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x02c1  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x02d3  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x02d6  */
    /* JADX WARN: Removed duplicated region for block: B:99:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r14v5, types: [kotlinx.coroutines.flow.X] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:38:0x0222 -> B:39:0x0238). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i r47, com.quizlet.features.infra.studysetting.data.QuestionSettings r48, kotlin.coroutines.jvm.internal.c r49) {
        /*
            Method dump skipped, instructions count: 743
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i.A(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i, com.quizlet.features.infra.studysetting.data.QuestionSettings, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void B() {
        com.quizlet.features.infra.basestudy.manager.f fVar = this.r;
        com.quizlet.features.infra.studysetting.managers.a aVarG = fVar.g();
        aVarG.getClass();
        boolean zD = com.quizlet.features.infra.studysetting.managers.a.d(aVarG, E1.GUIDANCE_DISABLED);
        long j = fVar.u;
        com.quizlet.learn.logging.a aVar = this.e;
        if (zD) {
            aVar.b(j, CollectionsKt.S(aVarG.c().s, ", ", null, null, new z(16), 30));
            return;
        }
        y yVarG = aVarG.g();
        com.quizlet.studiablemodels.assistantMode.a aVarF = aVarG.f();
        aVar.b(j, (yVarG == null || aVarF == null) ? "" : CollectionsKt.S(j3.b(G2.b(K6.c(aVarF), yVarG)), ", ", null, null, new com.quizlet.features.practicetest.navigation.a(14), 30));
    }

    public final void C(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.h event) {
        Object value;
        o oVar;
        Object value2;
        o oVar2;
        Intrinsics.checkNotNullParameter(event, "event");
        boolean zB = Intrinsics.b(event, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.b.a);
        s0 s0Var = this.p;
        com.quizlet.features.infra.basestudy.manager.f studyModeManager = this.r;
        if (zB) {
            com.quizlet.login.common.interactors.d dVar = this.g;
            dVar.getClass();
            Intrinsics.checkNotNullParameter(studyModeManager, "studyModeManager");
            long j = studyModeManager.u;
            com.quizlet.learn.logging.a aVar = (com.quizlet.learn.logging.a) dVar.b;
            aVar.a(LearnEventLog.Companion.a(LearnEventLog.b, LearnEventAction.b, Long.valueOf(j), null, 28));
            LearnEventLog learnEventLog = new LearnEventLog(null, 1, null);
            learnEventLog.setAction(LearnEventAction.h.getValue());
            learnEventLog.setPayload(new LearnEventLog.LearnPayload.TasksOptOut(Long.valueOf(studyModeManager.u), true));
            aVar.a(learnEventLog);
            com.quizlet.features.infra.studysetting.managers.a aVarG = studyModeManager.g();
            aVarG.getClass();
            aVarG.m(E1.GUIDANCE_DISABLED, true);
            aVarG.o(com.quizlet.studiablemodels.assistantMode.a.b);
            aVarG.p(y.b);
            do {
                value2 = s0Var.getValue();
                oVar2 = (o) value2;
                Intrinsics.e(oVar2, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUiState.Content");
            } while (!s0Var.k(value2, m.a((m) oVar2, false, 261119)));
            return;
        }
        boolean zB2 = Intrinsics.b(event, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.c.a);
        d0 d0Var = this.q;
        if (zB2) {
            d0Var.h(j.a);
            return;
        }
        if (Intrinsics.b(event, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.f.a)) {
            do {
                value = s0Var.getValue();
                oVar = (o) value;
                Intrinsics.e(oVar, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUiState.Content");
            } while (!s0Var.k(value, m.a((m) oVar, false, 260095)));
            return;
        }
        boolean z = event instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.a;
        com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.d dVar2 = this.c;
        if (z) {
            LearnSettingsResult learnSettingsResultA = dVar2.a(studyModeManager, ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.a) event).a, false);
            B();
            d0Var.h(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.i(learnSettingsResultA));
            return;
        }
        if (event instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.d) {
            E.A(p0.j(this), null, null, new f(this, ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.d) event).a, null), 3);
            return;
        }
        if (event instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.e) {
            F(((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.e) event).a);
            return;
        }
        if (!(event instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.g)) {
            throw new NoWhenBranchMatchedException();
        }
        LearnSettingsUpdateData learnSettingsUpdateData = ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.g) event).a;
        long j2 = studyModeManager.u;
        String value3 = WriteTransitionScreenName.a.getValue();
        com.quizlet.features.setpage.logging.writetransition.a aVar2 = this.k;
        aVar2.getClass();
        WriteTransitionEventLog.Companion companion = WriteTransitionEventLog.b;
        String setId = String.valueOf(j2);
        companion.getClass();
        Intrinsics.checkNotNullParameter(setId, "setId");
        WriteTransitionEventLog writeTransitionEventLog = new WriteTransitionEventLog(new WriteTransitionPayload(setId, value3, Integer.valueOf(A1.WRITE.a())));
        writeTransitionEventLog.setAction(WriteTransitionEventAction.a.getValue());
        aVar2.a.l(writeTransitionEventLog);
        LearnSettingsResult learnSettingsResultA2 = dVar2.a(studyModeManager, learnSettingsUpdateData, false);
        B();
        d0Var.h(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.i(learnSettingsResultA2));
    }

    public final void D() {
        m0 m0Var = this.b;
        Object objA = m0Var.a("studyableModelData");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        StudyableModelData studyableModelData = (StudyableModelData) objA;
        Object objA2 = m0Var.a("studySessionId");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        String str = (String) objA2;
        G1 studyableType = studyableModelData.getStudyableType();
        Long lValueOf = Long.valueOf(studyableModelData.k());
        Object objA3 = m0Var.a("studyableModelLocalId");
        if (objA3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        Long l = (Long) objA3;
        Object objA4 = m0Var.a("selectedOnlyIntent");
        if (objA4 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.s.e(str, studyableType, 1, null, lValueOf, l, (Boolean) objA4, "settings", null);
        this.r.m();
    }

    public final void E() {
        m0 m0Var = this.b;
        Object objA = m0Var.a("studyableModelData");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        StudyableModelData studyableModelData = (StudyableModelData) objA;
        Object objA2 = m0Var.a("studySessionId");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        String str = (String) objA2;
        G1 studyableType = studyableModelData.getStudyableType();
        Long lValueOf = Long.valueOf(studyableModelData.k());
        Object objA3 = m0Var.a("studyableModelLocalId");
        if (objA3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        Long l = (Long) objA3;
        Object objA4 = m0Var.a("selectedOnlyIntent");
        if (objA4 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.s.f(str, studyableType, 1, null, lValueOf, l, (Boolean) objA4, "settings");
    }

    public final void F(LearnSettingsUpdateData learnSettingsUpdateData) {
        l lVar = this.d;
        lVar.getClass();
        com.quizlet.features.infra.basestudy.manager.f studyModeManager = this.r;
        Intrinsics.checkNotNullParameter(studyModeManager, "studyModeManager");
        Intrinsics.checkNotNullParameter(learnSettingsUpdateData, "learnSettingsUpdateData");
        ((EventLogger) lVar.b).q("settings_revert_to_old");
        LearnSettingsResult learnSettingsResultA = ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.d) lVar.c).a(studyModeManager, learnSettingsUpdateData, true);
        B();
        this.q.h(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.i(learnSettingsResultA));
    }
}
