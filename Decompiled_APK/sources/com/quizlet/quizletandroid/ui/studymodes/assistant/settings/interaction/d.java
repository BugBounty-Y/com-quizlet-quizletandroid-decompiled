package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction;

import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.quizlet.db.data.models.persisted.DBUserStudyable;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.generated.enums.E1;
import com.quizlet.infra.legacysyncengine.net.f;
import com.quizlet.learn.settings.data.LearnSettingsResult;
import com.quizlet.learn.settings.data.WrittenQuestionGradingOption;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUpdateData;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final com.quizlet.quizletandroid.managers.upgrade.a a;
    public final f b;

    public d(com.quizlet.quizletandroid.managers.upgrade.a settingsValidator, u shouldGenerateNewPromptUseCase, f syncDispatcher) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(settingsValidator, "settingsValidator");
        Intrinsics.checkNotNullParameter(shouldGenerateNewPromptUseCase, "shouldGenerateNewPromptUseCase");
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.a = settingsValidator;
        this.b = syncDispatcher;
    }

    public final LearnSettingsResult a(com.quizlet.features.infra.basestudy.manager.f studyModeManager, LearnSettingsUpdateData learnSettingsUpdateData, boolean z) {
        Intrinsics.checkNotNullParameter(studyModeManager, "studyModeManager");
        Intrinsics.checkNotNullParameter(learnSettingsUpdateData, "learnSettingsUpdateData");
        com.quizlet.features.infra.studysetting.managers.a aVarG = studyModeManager.g();
        QuestionSettings questionSettingsC = aVarG.c();
        boolean z2 = learnSettingsUpdateData.a;
        ArrayList arrayListC = M6.c(learnSettingsUpdateData.d, learnSettingsUpdateData.e, learnSettingsUpdateData.f);
        WrittenQuestionGradingOption writtenQuestionGradingOption = learnSettingsUpdateData.l;
        QuestionSettings questionSettingsA = QuestionSettings.a(questionSettingsC, null, arrayListC, learnSettingsUpdateData.b, learnSettingsUpdateData.g, learnSettingsUpdateData.h, learnSettingsUpdateData.i, false, false, false, null, null, false, writtenQuestionGradingOption.d, writtenQuestionGradingOption.c, z2, learnSettingsUpdateData.c, 16321);
        List list = studyModeManager.x.x;
        if (z) {
            long jCurrentTimeMillis = System.currentTimeMillis();
            questionSettingsA = QuestionSettings.a(questionSettingsA, null, null, false, false, false, false, false, false, false, null, Long.valueOf(jCurrentTimeMillis), false, false, false, false, false, 261119);
            Intrinsics.d(list);
            DBUserStudyable dBUserStudyable = (DBUserStudyable) CollectionsKt.firstOrNull(list);
            if (dBUserStudyable != null) {
                dBUserStudyable.setStartTimestampSec(Long.valueOf(TimeUnit.MILLISECONDS.toSeconds(jCurrentTimeMillis)));
            }
            aVarG.m(E1.GUIDANCE_DISABLED, false);
        }
        QuestionSettings questionSettings = questionSettingsA;
        boolean zEquals = questionSettings.equals(questionSettingsC);
        boolean z3 = learnSettingsUpdateData.k;
        boolean z4 = learnSettingsUpdateData.j;
        if (zEquals && !z4 && !z3) {
            return LearnSettingsResult.NotUpdated.a;
        }
        QuestionSettings questionSettingsG = this.a.g(questionSettings, questionSettingsC);
        aVarG.l(questionSettingsG);
        this.b.b(list);
        return new LearnSettingsResult.Updated(questionSettingsG, questionSettingsG.c != questionSettingsC.c, (z || z3 || !u.j(questionSettingsC, questionSettingsG, z4)) ? false : true, !z && z4, z, learnSettingsUpdateData.k);
    }
}
