package com.braze.ui.actions.brazeactions.steps;

import android.content.Context;
import com.braze.IBrazeDeeplinkHandler;
import com.braze.ui.BrazeDeeplinkHandler;
import com.braze.ui.actions.UriAction;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class OpenLinkExternallyStep extends BaseBrazeActionStep {

    @NotNull
    public static final OpenLinkExternallyStep INSTANCE = new OpenLinkExternallyStep();

    private OpenLinkExternallyStep() {
        super(null);
    }

    @Override // com.braze.ui.actions.brazeactions.steps.IBrazeActionStep
    public boolean isValid(@NotNull StepData data) {
        Intrinsics.checkNotNullParameter(data, "data");
        return StepData.isArgCountInBounds$default(data, 0, new IntRange(1, 2, 1), 1, null) && data.isArgString(0);
    }

    @Override // com.braze.ui.actions.brazeactions.steps.IBrazeActionStep
    public void run(@NotNull Context context, @NotNull StepData data) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(data, "data");
        String strValueOf = String.valueOf(data.getFirstArg());
        IBrazeDeeplinkHandler companion = BrazeDeeplinkHandler.Companion.getInstance();
        UriAction uriActionCreateUriActionFromUrlString = companion.createUriActionFromUrlString(strValueOf, null, false, data.getChannel());
        if (uriActionCreateUriActionFromUrlString != null) {
            companion.gotoUri(context, uriActionCreateUriActionFromUrlString);
        }
    }
}
