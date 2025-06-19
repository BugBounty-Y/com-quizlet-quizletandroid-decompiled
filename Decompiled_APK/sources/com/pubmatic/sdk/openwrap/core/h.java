package com.pubmatic.sdk.openwrap.core;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface h {
    f getBid();

    @Deprecated
    void proceedOnError(@NonNull g gVar);

    void proceedOnError(@NonNull g gVar, @NonNull String str);

    boolean proceedToLoadAd();

    void setBidEventListener(k kVar);
}
