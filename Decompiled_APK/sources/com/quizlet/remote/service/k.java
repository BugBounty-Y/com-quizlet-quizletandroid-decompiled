package com.quizlet.remote.service;

import com.quizlet.remote.model.entitlements.RemoteEntitlementResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface k {
    @retrofit2.http.f("entitlements/v2/{premiumFeatureIdentifier}")
    Object a(@retrofit2.http.s("premiumFeatureIdentifier") @NotNull String str, @NotNull kotlin.coroutines.h<? super RemoteEntitlementResponse> hVar);
}
