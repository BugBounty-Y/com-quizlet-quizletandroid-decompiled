package com.quizlet.quizletandroid.ui.studymodes.assistant;

import com.quizlet.learn.data.L;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ L b;

    public /* synthetic */ d(L l, int i) {
        this.a = i;
        this.b = l;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        L l = this.b;
        switch (this.a) {
            case 0:
                String str = LearningAssistantActivity.D;
                l.e.invoke();
                break;
            default:
                String str2 = LearningAssistantActivity.D;
                l.f.invoke();
                break;
        }
        return Unit.a;
    }
}
