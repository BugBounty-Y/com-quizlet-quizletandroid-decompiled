package com.quizlet.api.model;

import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public interface ISkuDetails {
    long getPriceAmountMicros();

    @NotNull
    String getPriceCurrencyCode();
}
