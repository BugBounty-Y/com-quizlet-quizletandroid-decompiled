package com.appsflyer;

import java.util.Map;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface AppsFlyerInAppPurchaseValidationCallback {
    void onInAppPurchaseValidationError(@NotNull Map<String, ? extends Object> map);

    void onInAppPurchaseValidationFinished(@NotNull Map<String, ? extends Object> map);
}
