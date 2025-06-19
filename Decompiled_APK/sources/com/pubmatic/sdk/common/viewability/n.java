package com.pubmatic.sdk.common.viewability;

import android.content.Context;
import android.view.View;
import androidx.annotation.NonNull;
import java.util.List;

/* loaded from: classes2.dex */
public interface n extends d {
    @Override // com.pubmatic.sdk.common.viewability.d, com.pubmatic.sdk.common.viewability.i
    /* synthetic */ void addFriendlyObstructions(@NonNull View view, @NonNull h hVar);

    @Override // com.pubmatic.sdk.common.viewability.d
    /* synthetic */ void finishAdSession();

    void impressionOccurred();

    void loaded(boolean z, float f);

    @Override // com.pubmatic.sdk.common.viewability.d
    @NonNull
    /* synthetic */ String omSDKVersion();

    @Override // com.pubmatic.sdk.common.viewability.d
    /* synthetic */ void omidJsServiceScript(@NonNull Context context, @NonNull c cVar);

    @Override // com.pubmatic.sdk.common.viewability.d, com.pubmatic.sdk.common.viewability.i
    /* synthetic */ void removeFriendlyObstructions(View view);

    @Override // com.pubmatic.sdk.common.viewability.d
    /* synthetic */ void setTrackView(@NonNull View view);

    void signalAdEvent(@NonNull com.pubmatic.sdk.common.g gVar);

    void signalError(@NonNull l lVar, @NonNull String str);

    void signalPlayerStateChange(@NonNull m mVar);

    void start(float f, float f2);

    void startAdSession(View view, @NonNull List<j> list, @NonNull k kVar);
}
