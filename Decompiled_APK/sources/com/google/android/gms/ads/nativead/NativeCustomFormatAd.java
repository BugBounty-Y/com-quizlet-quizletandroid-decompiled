package com.google.android.gms.ads.nativead;

import androidx.annotation.NonNull;
import com.google.android.gms.ads.m;
import java.util.List;

/* loaded from: classes2.dex */
public interface NativeCustomFormatAd {

    @NonNull
    public static final String ASSET_NAME_VIDEO = "_videoMediaView";

    void destroy();

    List<String> getAvailableAssetNames();

    String getCustomFormatId();

    @NonNull
    e getDisplayOpenMeasurement();

    c getImage(@NonNull String str);

    m getMediaContent();

    CharSequence getText(@NonNull String str);

    void performClick(@NonNull String str);

    void recordImpression();
}
