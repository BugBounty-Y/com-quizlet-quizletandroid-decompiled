package com.quizlet.features.universaluploadflow.pastetext.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class b implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ d b;

    public /* synthetic */ b(d dVar, int i) {
        this.a = i;
        this.b = dVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.A(com.quizlet.features.universaluploadflow.pastetext.data.c.a);
                break;
            default:
                this.b.A(com.quizlet.features.universaluploadflow.pastetext.data.c.a);
                break;
        }
        return Unit.a;
    }
}
