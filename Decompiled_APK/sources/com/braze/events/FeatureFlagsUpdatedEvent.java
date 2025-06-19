package com.braze.events;

import com.braze.models.FeatureFlag;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class FeatureFlagsUpdatedEvent {
    public static final Companion Companion = new Companion(null);
    private final List<FeatureFlag> featureFlags;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    public FeatureFlagsUpdatedEvent(List<FeatureFlag> featureFlags) {
        Intrinsics.checkNotNullParameter(featureFlags, "featureFlags");
        this.featureFlags = featureFlags;
    }

    public String toString() {
        return "FeatureFlagsUpdatedEvent{flag count=" + this.featureFlags.size() + '}';
    }
}
