package com.braze.ui.actions.brazeactions.steps;

import android.content.Context;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface IBrazeActionStep {
    boolean isValid(@NotNull StepData stepData);

    void run(@NotNull Context context, @NotNull StepData stepData);
}
