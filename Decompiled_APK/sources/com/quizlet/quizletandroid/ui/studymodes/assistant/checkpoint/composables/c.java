package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.composables;

import kotlin.Unit;
import kotlin.collections.B;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.d;

/* loaded from: classes3.dex */
public final class c implements d {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    public /* synthetic */ c(int i, Function1 function1) {
        this.a = i;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.d
    public final Object invoke(Object obj, Object obj2, Object obj3, Object obj4) {
        switch (this.a) {
            case 0:
                this.b.invoke(new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.d(((Number) obj).longValue(), B.j((String) obj3, (String) obj4), ((Boolean) obj2).booleanValue()));
                break;
            case 1:
                this.b.invoke(new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.d(((Number) obj).longValue(), B.j((String) obj3, (String) obj4), ((Boolean) obj2).booleanValue()));
                break;
            default:
                this.b.invoke(new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.d(((Number) obj).longValue(), B.j((String) obj3, (String) obj4), ((Boolean) obj2).booleanValue()));
                break;
        }
        return Unit.a;
    }
}
