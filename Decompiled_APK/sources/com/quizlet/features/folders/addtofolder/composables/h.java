package com.quizlet.features.folders.addtofolder.composables;

import androidx.navigation.compose.B;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class h implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ int c;
    public final /* synthetic */ InterfaceC4938g d;

    public /* synthetic */ h(InterfaceC4938g interfaceC4938g, Object obj, int i, int i2) {
        this.a = i2;
        this.d = interfaceC4938g;
        this.b = obj;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                com.quizlet.features.folders.addtofolder.data.s sVar = (com.quizlet.features.folders.addtofolder.data.s) this.b;
                ((B) this.d).invoke(new com.quizlet.features.folders.addtofolder.data.f(sVar.a, this.c));
                break;
            case 1:
                ((com.quizlet.explanations.questiondetail.ui.composables.l) this.d).invoke((com.quizlet.features.folders.addtofolder.data.s) this.b, Integer.valueOf(this.c));
                break;
            default:
                ((com.quizlet.explanations.questiondetail.ui.composables.l) this.d).invoke((com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f) this.b, Integer.valueOf(this.c));
                break;
        }
        return Unit.a;
    }
}
