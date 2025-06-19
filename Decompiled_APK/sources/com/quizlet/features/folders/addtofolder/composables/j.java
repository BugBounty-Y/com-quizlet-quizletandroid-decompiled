package com.quizlet.features.folders.addtofolder.composables;

import com.quizlet.assembly.compose.modals.x;
import com.quizlet.features.notes.common.events.K;
import com.quizlet.features.practicetest.detail.data.C4399b;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class j implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ x b;
    public final /* synthetic */ Function1 c;

    public /* synthetic */ j(x xVar, Function1 function1, int i) {
        this.a = i;
        this.b = xVar;
        this.c = function1;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.c.invoke(com.quizlet.features.folders.addtofolder.data.b.a);
                this.b.a();
                break;
            case 1:
                this.b.a();
                this.c.invoke(com.quizlet.features.infra.folder.tag.screenstates.f.a);
                break;
            case 2:
                this.c.invoke(com.quizlet.features.notes.common.events.u.a);
                x.d(this.b);
                break;
            case 3:
                this.c.invoke(K.a);
                x.d(this.b);
                break;
            case 4:
                x.d(this.b);
                this.c.invoke(C4399b.a);
                break;
            case 5:
                this.c.invoke(new com.quizlet.features.practicetest.results.data.h(false));
                this.b.a();
                break;
            case 6:
                this.c.invoke(new com.quizlet.features.practicetest.results.data.h(true));
                x.d(this.b);
                break;
            case 7:
                this.b.a();
                this.c.invoke(com.quizlet.features.practicetest.takingtest.data.u.a);
                break;
            case 8:
                this.c.invoke(com.quizlet.features.practicetest.takingtest.data.q.a);
                x.d(this.b);
                break;
            case 9:
                this.c.invoke(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.f.a);
                this.b.a();
                break;
            default:
                this.c.invoke(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.f.a);
                this.b.a();
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ j(Function1 function1, x xVar, int i) {
        this.a = i;
        this.c = function1;
        this.b = xVar;
    }
}
