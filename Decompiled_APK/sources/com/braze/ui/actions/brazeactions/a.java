package com.braze.ui.actions.brazeactions;

import com.braze.ui.actions.brazeactions.BrazeActionParser;
import com.braze.ui.actions.brazeactions.steps.StepData;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ BrazeActionParser.ActionType b;
    public final /* synthetic */ StepData c;

    public /* synthetic */ a(BrazeActionParser.ActionType actionType, StepData stepData, int i) {
        this.a = i;
        this.b = actionType;
        this.c = stepData;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeActionParser.getActionType$lambda$9(this.b, this.c);
            default:
                return BrazeActionParser.parse$lambda$5(this.b, this.c);
        }
    }
}
