package com.quizlet.api.model;

import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public interface IPurchase {
    String getOrderId();

    @NotNull
    String getPackageName();

    @NotNull
    String getSku();

    @NotNull
    String getToken();
}
