package com.amazon.device.ads;

import androidx.annotation.NonNull;

/* loaded from: classes.dex */
public interface DTBAdCallback {
    void onFailure(@NonNull AdError adError);

    void onSuccess(@NonNull DTBAdResponse dTBAdResponse);
}
