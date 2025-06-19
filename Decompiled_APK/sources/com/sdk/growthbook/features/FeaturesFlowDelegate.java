package com.sdk.growthbook.features;

import com.sdk.growthbook.model.GBFeature;
import com.sdk.growthbook.utils.GBError;
import java.util.Map;
import kotlin.Metadata;
import kotlinx.serialization.json.v;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface FeaturesFlowDelegate {
    void featuresAPIModelSuccessfully(@NotNull FeaturesDataModel featuresDataModel);

    void featuresFetchFailed(@NotNull GBError gBError, boolean z);

    void featuresFetchedSuccessfully(@NotNull Map<String, GBFeature> map, boolean z);

    void savedGroupsFetchFailed(@NotNull GBError gBError, boolean z);

    void savedGroupsFetchedSuccessfully(@NotNull v vVar, boolean z);
}
