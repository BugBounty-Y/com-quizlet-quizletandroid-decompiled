package com.pubmatic.sdk.common.utility;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface m {
    void onErrorOpenUrl(@NonNull String str);

    void onInternalBrowserClose(@NonNull String str);

    void onInternalBrowserOpen(@NonNull String str);

    void onLeaveApp(@NonNull String str);
}
