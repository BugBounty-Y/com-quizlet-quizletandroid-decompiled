package com.pubmatic.sdk.common.viewability;

import android.content.Context;
import android.view.View;
import androidx.annotation.NonNull;
import java.util.List;

/* loaded from: classes2.dex */
public interface g extends d {
    @Override // com.pubmatic.sdk.common.viewability.d, com.pubmatic.sdk.common.viewability.i
    /* synthetic */ void addFriendlyObstructions(@NonNull View view, @NonNull h hVar);

    @Override // com.pubmatic.sdk.common.viewability.d
    /* synthetic */ void finishAdSession();

    @Override // com.pubmatic.sdk.common.viewability.d
    @NonNull
    /* synthetic */ String omSDKVersion();

    @Override // com.pubmatic.sdk.common.viewability.d
    /* synthetic */ void omidJsServiceScript(@NonNull Context context, @NonNull c cVar);

    @Override // com.pubmatic.sdk.common.viewability.d, com.pubmatic.sdk.common.viewability.i
    /* synthetic */ void removeFriendlyObstructions(View view);

    @Override // com.pubmatic.sdk.common.viewability.d
    /* synthetic */ void setTrackView(@NonNull View view);

    void signalAdEvent(@NonNull e eVar);

    void startAdSession(@NonNull View view, List<? extends j> list, @NonNull f fVar);
}
