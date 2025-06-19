package com.braze.ui.actions.brazeactions.steps;

import android.content.Context;
import com.braze.Braze;
import com.braze.BrazeUser;
import com.braze.enums.NotificationSubscriptionType;
import com.braze.support.BrazeLogger;
import com.braze.ui.actions.brazeactions.b;
import com.braze.ui.f;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class SetEmailSubscriptionStep extends BaseBrazeActionStep {

    @NotNull
    public static final SetEmailSubscriptionStep INSTANCE;

    @NotNull
    private static final String TAG;

    static {
        SetEmailSubscriptionStep setEmailSubscriptionStep = new SetEmailSubscriptionStep();
        INSTANCE = setEmailSubscriptionStep;
        TAG = BrazeLogger.INSTANCE.brazeLogTag(setEmailSubscriptionStep);
    }

    private SetEmailSubscriptionStep() {
        super(null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String run$lambda$1(StepData stepData) {
        return "Could not parse subscription type from data: " + stepData;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit run$lambda$2(NotificationSubscriptionType notificationSubscriptionType, BrazeUser it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.setEmailNotificationSubscriptionType(notificationSubscriptionType);
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
        NotificationSubscriptionType notificationSubscriptionTypeFromValue = NotificationSubscriptionType.Companion.fromValue(String.valueOf(data.getFirstArg()));
        if (notificationSubscriptionTypeFromValue == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new b(1, data), 7, (Object) null);
        } else {
            BaseBrazeActionStep.Companion.runOnUser$android_sdk_ui_release(Braze.Companion.getInstance(context), new f(notificationSubscriptionTypeFromValue, 2));
        }
    }
}
