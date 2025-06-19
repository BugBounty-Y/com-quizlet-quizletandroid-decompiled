package com.pubmatic.sdk.common.viewability;

import android.content.Context;
import android.view.View;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface d extends i {
    @Override // com.pubmatic.sdk.common.viewability.i
    /* synthetic */ void addFriendlyObstructions(@NonNull View view, @NonNull h hVar);

    void finishAdSession();

    @NonNull
    String omSDKVersion();

    void omidJsServiceScript(@NonNull Context context, @NonNull c cVar);

    @Override // com.pubmatic.sdk.common.viewability.i
    /* synthetic */ void removeFriendlyObstructions(View view);

    void setTrackView(@NonNull View view);
}
