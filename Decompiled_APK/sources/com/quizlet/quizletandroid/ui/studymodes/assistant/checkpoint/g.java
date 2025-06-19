package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import android.view.View;
import kotlin.Unit;

/* loaded from: classes3.dex */
public final /* synthetic */ class g implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ LearnCheckpointFragment b;

    public /* synthetic */ g(LearnCheckpointFragment learnCheckpointFragment, int i) {
        this.a = i;
        this.b = learnCheckpointFragment;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        LearnCheckpointFragment learnCheckpointFragment = this.b;
        switch (this.a) {
            case 0:
                String str = LearnCheckpointFragment.o;
                learnCheckpointFragment.T().f.j(Unit.a);
                break;
            case 1:
                String str2 = LearnCheckpointFragment.o;
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d dVarT = learnCheckpointFragment.T();
                dVarT.getClass();
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar = com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o.a;
                dVarT.h = oVar;
                dVarT.e.j(new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.j(dVarT.i.a(oVar)));
                break;
            default:
                String str3 = LearnCheckpointFragment.o;
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d dVarT2 = learnCheckpointFragment.T();
                dVarT2.getClass();
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar2 = com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o.b;
                dVarT2.h = oVar2;
                dVarT2.e.j(new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.j(dVarT2.i.a(oVar2)));
                break;
        }
    }
}
