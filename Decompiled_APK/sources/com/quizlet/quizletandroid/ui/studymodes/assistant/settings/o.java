package com.quizlet.quizletandroid.ui.studymodes.assistant.settings;

import androidx.compose.runtime.C0776c;
import com.quizlet.features.infra.studysetting.data.GradingSettingsValues;
import com.quizlet.learn.settings.data.WrittenQuestionGradingOption;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUpdateData;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class o implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m b;

    public /* synthetic */ o(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m mVar, int i) {
        this.a = i;
        this.b = mVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m mVar = this.b;
                GradingSettingsValues gradingSettingsValues = mVar.m;
                boolean z = gradingSettingsValues.b;
                boolean z2 = gradingSettingsValues.c;
                return C0776c.z(new LearnSettingsUpdateData(mVar.b, mVar.c, mVar.d, mVar.e, mVar.f, mVar.g, mVar.h, mVar.i, mVar.j, false, false, (z && z2) ? WrittenQuestionGradingOption.Relaxed.e : z2 ? WrittenQuestionGradingOption.Moderate.e : WrittenQuestionGradingOption.Strict.e));
            case 1:
                return C0776c.z(this.b.m);
            default:
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m mVar2 = this.b;
                GradingSettingsValues gradingSettingsValues2 = mVar2.m;
                boolean z3 = gradingSettingsValues2.b;
                boolean z4 = gradingSettingsValues2.c;
                return C0776c.z(new LearnSettingsUpdateData(mVar2.b, mVar2.c, mVar2.d, mVar2.e, mVar2.f, mVar2.g, mVar2.h, mVar2.i, mVar2.j, false, false, (z3 && z4) ? WrittenQuestionGradingOption.Relaxed.e : z4 ? WrittenQuestionGradingOption.Moderate.e : WrittenQuestionGradingOption.Strict.e));
        }
    }
}
