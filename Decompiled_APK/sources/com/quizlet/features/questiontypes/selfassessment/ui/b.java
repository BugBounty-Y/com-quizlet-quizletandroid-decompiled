package com.quizlet.features.questiontypes.selfassessment.ui;

import com.quizlet.studiablemodels.StudiableImage;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ StudiableImage c;

    public /* synthetic */ b(Function1 function1, StudiableImage studiableImage, int i) {
        this.a = i;
        this.b = function1;
        this.c = studiableImage;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                this.b.invoke(this.c);
                break;
            default:
                this.b.invoke(this.c);
                break;
        }
        return Unit.a;
    }
}
