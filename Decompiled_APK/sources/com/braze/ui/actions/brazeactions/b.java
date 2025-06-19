package com.braze.ui.actions.brazeactions;

import com.braze.ui.actions.brazeactions.steps.SetEmailSubscriptionStep;
import com.braze.ui.actions.brazeactions.steps.SetPushNotificationSubscriptionStep;
import com.braze.ui.actions.brazeactions.steps.StepData;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class b implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ StepData b;

    public /* synthetic */ b(int i, StepData stepData) {
        this.a = i;
        this.b = stepData;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeActionParser.parse$lambda$6(this.b);
            case 1:
                return SetEmailSubscriptionStep.run$lambda$1(this.b);
            case 2:
                return SetPushNotificationSubscriptionStep.run$lambda$1(this.b);
            case 3:
                return StepData.args_delegate$lambda$0(this.b);
            case 4:
                return StepData.firstArg_delegate$lambda$1(this.b);
            default:
                return StepData.secondArg_delegate$lambda$2(this.b);
        }
    }
}
