package com.quizlet.features.notes.detail.composables.common;

import com.quizlet.data.model.EssayInfo;
import com.quizlet.features.notes.common.events.C4370a;
import com.quizlet.features.notes.common.events.s;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ EssayInfo b;
    public final /* synthetic */ Function1 c;

    public /* synthetic */ a(EssayInfo essayInfo, Function1 function1) {
        this.b = essayInfo;
        this.c = function1;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.c.invoke(new C4370a(this.b));
                break;
            default:
                EssayInfo essayInfo = this.b;
                if (essayInfo != null) {
                    this.c.invoke(new s(essayInfo));
                }
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(Function1 function1, EssayInfo essayInfo) {
        this.c = function1;
        this.b = essayInfo;
    }
}
