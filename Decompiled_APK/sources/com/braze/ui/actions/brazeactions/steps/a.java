package com.braze.ui.actions.brazeactions.steps;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ StepData c;

    public /* synthetic */ a(int i, StepData stepData, int i2) {
        this.a = i2;
        this.b = i;
        this.c = stepData;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return StepData.isArgString$lambda$5(this.b, this.c);
            case 1:
                return StepData.isArgOptionalJsonObject$lambda$6(this.b, this.c);
            default:
                return StepData.isArgCountInBounds$lambda$3(this.b, this.c);
        }
    }
}
