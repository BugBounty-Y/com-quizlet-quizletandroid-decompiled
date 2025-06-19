package com.sdk.growthbook.stickybucket;

import com.sdk.growthbook.utils.GBStickyAssignmentsDocument;
import java.util.Map;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface GBStickyBucketService {
    @NotNull
    Map<String, GBStickyAssignmentsDocument> getAllAssignments(@NotNull Map<String, String> map);

    GBStickyAssignmentsDocument getAssignments(@NotNull String str, @NotNull String str2);

    void saveAssignments(@NotNull GBStickyAssignmentsDocument gBStickyAssignmentsDocument);
}
