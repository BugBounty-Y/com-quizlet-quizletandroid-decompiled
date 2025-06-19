package com.braze.ui.actions.brazeactions.steps;

import android.content.Context;
import androidx.navigation.internal.h;
import com.braze.Braze;
import com.braze.BrazeUser;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AddToSubscriptionGroupStep extends BaseBrazeActionStep {

    @NotNull
    public static final AddToSubscriptionGroupStep INSTANCE = new AddToSubscriptionGroupStep();

    private AddToSubscriptionGroupStep() {
        super(null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit run$lambda$1(String str, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.addToSubscriptionGroup(str);
        return Unit.a;
    }

    @Override // com.braze.ui.actions.brazeactions.steps.IBrazeActionStep
    public boolean isValid(@NotNull StepData data) {
        Intrinsics.checkNotNullParameter(data, "data");
        return StepData.isArgCountInBounds$default(data, 1, null, 2, null) && data.isArgString(0);
    }

    @Override // com.braze.ui.actions.brazeactions.steps.IBrazeActionStep
    public void run(@NotNull Context context, @NotNull StepData data) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(data, "data");
        BaseBrazeActionStep.Companion.runOnUser$android_sdk_ui_release(Braze.Companion.getInstance(context), new h(String.valueOf(data.getFirstArg()), 11));
    }
}
