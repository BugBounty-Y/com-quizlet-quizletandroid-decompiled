package com.quizlet.features.questionnaire.options;

import com.quizlet.features.questionnaire.navigation.Control;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class a implements Function0 {
    public final /* synthetic */ Function1 a;
    public final /* synthetic */ Control.Button b;

    public a(Function1 function1, Control.Button button) {
        this.a = function1;
        this.b = button;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        this.a.invoke(this.b);
        return Unit.a;
    }
}
