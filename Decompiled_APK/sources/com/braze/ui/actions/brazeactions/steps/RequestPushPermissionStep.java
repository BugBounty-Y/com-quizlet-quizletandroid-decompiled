package com.braze.ui.actions.brazeactions.steps;

import android.content.Context;
import com.braze.BrazeActivityLifecycleCallbackListener;
import com.braze.support.PermissionUtils;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class RequestPushPermissionStep extends BaseBrazeActionStep {

    @NotNull
    public static final RequestPushPermissionStep INSTANCE = new RequestPushPermissionStep();

    private RequestPushPermissionStep() {
        super(null);
    }

    @Override // com.braze.ui.actions.brazeactions.steps.IBrazeActionStep
    public boolean isValid(@NotNull StepData data) {
        Intrinsics.checkNotNullParameter(data, "data");
        return true;
    }

    @Override // com.braze.ui.actions.brazeactions.steps.IBrazeActionStep
    public void run(@NotNull Context context, @NotNull StepData data) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(data, "data");
        PermissionUtils.requestPushPermissionPrompt(BrazeActivityLifecycleCallbackListener.Companion.getActivity());
    }
}
