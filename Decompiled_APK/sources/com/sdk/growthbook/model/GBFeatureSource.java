package com.sdk.growthbook.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public final class GBFeatureSource {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ GBFeatureSource[] $VALUES;
    public static final GBFeatureSource unknownFeature = new GBFeatureSource("unknownFeature", 0);
    public static final GBFeatureSource defaultValue = new GBFeatureSource("defaultValue", 1);
    public static final GBFeatureSource force = new GBFeatureSource("force", 2);
    public static final GBFeatureSource experiment = new GBFeatureSource("experiment", 3);
    public static final GBFeatureSource cyclicPrerequisite = new GBFeatureSource("cyclicPrerequisite", 4);
    public static final GBFeatureSource prerequisite = new GBFeatureSource("prerequisite", 5);
    public static final GBFeatureSource override = new GBFeatureSource("override", 6);

    private static final /* synthetic */ GBFeatureSource[] $values() {
        return new GBFeatureSource[]{unknownFeature, defaultValue, force, experiment, cyclicPrerequisite, prerequisite, override};
    }

    static {
        GBFeatureSource[] gBFeatureSourceArr$values = $values();
        $VALUES = gBFeatureSourceArr$values;
        $ENTRIES = AbstractC3328d.f(gBFeatureSourceArr$values);
    }

    private GBFeatureSource(String str, int i) {
    }

    @NotNull
    public static a getEntries() {
        return $ENTRIES;
    }

    public static GBFeatureSource valueOf(String str) {
        return (GBFeatureSource) Enum.valueOf(GBFeatureSource.class, str);
    }

    public static GBFeatureSource[] values() {
        return (GBFeatureSource[]) $VALUES.clone();
    }
}
