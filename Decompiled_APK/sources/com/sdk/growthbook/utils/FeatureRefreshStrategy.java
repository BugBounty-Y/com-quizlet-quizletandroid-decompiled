package com.sdk.growthbook.utils;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public final class FeatureRefreshStrategy {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ FeatureRefreshStrategy[] $VALUES;
    public static final FeatureRefreshStrategy STALE_WHILE_REVALIDATE = new FeatureRefreshStrategy("STALE_WHILE_REVALIDATE", 0);
    public static final FeatureRefreshStrategy SERVER_SENT_EVENTS = new FeatureRefreshStrategy("SERVER_SENT_EVENTS", 1);
    public static final FeatureRefreshStrategy SERVER_SENT_REMOTE_FEATURE_EVAL = new FeatureRefreshStrategy("SERVER_SENT_REMOTE_FEATURE_EVAL", 2);

    private static final /* synthetic */ FeatureRefreshStrategy[] $values() {
        return new FeatureRefreshStrategy[]{STALE_WHILE_REVALIDATE, SERVER_SENT_EVENTS, SERVER_SENT_REMOTE_FEATURE_EVAL};
    }

    static {
        FeatureRefreshStrategy[] featureRefreshStrategyArr$values = $values();
        $VALUES = featureRefreshStrategyArr$values;
        $ENTRIES = AbstractC3328d.f(featureRefreshStrategyArr$values);
    }

    private FeatureRefreshStrategy(String str, int i) {
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static FeatureRefreshStrategy valueOf(String str) {
        return (FeatureRefreshStrategy) Enum.valueOf(FeatureRefreshStrategy.class, str);
    }

    public static FeatureRefreshStrategy[] values() {
        return (FeatureRefreshStrategy[]) $VALUES.clone();
    }
}
