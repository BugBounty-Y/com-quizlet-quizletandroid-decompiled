package com.quizlet.features.infra.basestudy.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUpdateData;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class g implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ x b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ InterfaceC0773a0 d;

    public /* synthetic */ g(x xVar, Function1 function1, InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = xVar;
        this.c = function1;
        this.d = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.a();
                Boolean bool = (Boolean) this.d.getValue();
                bool.booleanValue();
                this.c.invoke(bool);
                break;
            case 1:
                this.b.a();
                Boolean bool2 = (Boolean) this.d.getValue();
                bool2.booleanValue();
                this.c.invoke(bool2);
                break;
            default:
                this.b.a();
                this.c.invoke(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.e((LearnSettingsUpdateData) this.d.getValue()));
                break;
        }
        return Unit.a;
    }
}
