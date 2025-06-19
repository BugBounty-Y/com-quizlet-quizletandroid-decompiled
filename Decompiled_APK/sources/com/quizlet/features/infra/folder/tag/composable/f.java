package com.quizlet.features.infra.folder.tag.composable;

import androidx.compose.runtime.InterfaceC0773a0;
import com.quizlet.features.notes.common.events.A;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUpdateData;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.LearnSettingsGradingUpdateData;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ InterfaceC0773a0 c;

    public /* synthetic */ f(int i, InterfaceC0773a0 interfaceC0773a0, Function1 function1) {
        this.a = i;
        this.b = function1;
        this.c = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                InterfaceC0773a0 interfaceC0773a0 = this.c;
                this.b.invoke(new com.quizlet.features.infra.folder.tag.screenstates.d((String) interfaceC0773a0.getValue(), false));
                interfaceC0773a0.setValue("");
                break;
            case 1:
                this.b.invoke((String) this.c.getValue());
                break;
            case 2:
                this.b.invoke(new A((String) this.c.getValue()));
                break;
            case 3:
                this.b.invoke((String) this.c.getValue());
                break;
            case 4:
                this.c.setValue("");
                this.b.invoke(null);
                break;
            case 5:
                this.b.invoke((String) this.c.getValue());
                break;
            case 6:
                this.b.invoke(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.a((LearnSettingsUpdateData) this.c.getValue()));
                break;
            case 7:
                InterfaceC0773a0 interfaceC0773a02 = this.c;
                interfaceC0773a02.setValue(LearnSettingsUpdateData.a((LearnSettingsUpdateData) interfaceC0773a02.getValue(), false, false, false, false, false, false, false, false, false, null, 3071));
                this.b.invoke(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.g((LearnSettingsUpdateData) interfaceC0773a02.getValue()));
                break;
            case 8:
                this.b.invoke(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.d((LearnSettingsUpdateData) this.c.getValue()));
                break;
            case 9:
                InterfaceC0773a0 interfaceC0773a03 = this.c;
                interfaceC0773a03.setValue(LearnSettingsUpdateData.a((LearnSettingsUpdateData) interfaceC0773a03.getValue(), false, false, false, false, false, false, false, false, false, null, 3583));
                this.b.invoke(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.b.a);
                break;
            case 10:
                this.b.invoke(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.a((LearnSettingsUpdateData) this.c.getValue()));
                break;
            case 11:
                this.b.invoke(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.a((LearnSettingsGradingUpdateData) this.c.getValue()));
                break;
            default:
                Integer num = (Integer) this.c.getValue();
                if (num != null) {
                    this.b.invoke(new com.quizlet.report.data.f(num.intValue()));
                }
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ f(InterfaceC0773a0 interfaceC0773a0, Function1 function1) {
        this.a = 12;
        this.c = interfaceC0773a0;
        this.b = function1;
    }
}
