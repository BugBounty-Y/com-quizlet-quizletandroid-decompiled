package com.skydoves.balloon;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.skydoves.balloon.annotations.InternalBalloonApi;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
@InternalBalloonApi
/* loaded from: classes3.dex */
public final class PlacementType {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ PlacementType[] $VALUES;
    public static final PlacementType ALIGNMENT = new PlacementType("ALIGNMENT", 0);
    public static final PlacementType DROPDOWN = new PlacementType("DROPDOWN", 1);
    public static final PlacementType CENTER = new PlacementType("CENTER", 2);

    private static final /* synthetic */ PlacementType[] $values() {
        return new PlacementType[]{ALIGNMENT, DROPDOWN, CENTER};
    }

    static {
        PlacementType[] placementTypeArr$values = $values();
        $VALUES = placementTypeArr$values;
        $ENTRIES = AbstractC3328d.f(placementTypeArr$values);
    }

    private PlacementType(String str, int i) {
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static PlacementType valueOf(String str) {
        return (PlacementType) Enum.valueOf(PlacementType.class, str);
    }

    public static PlacementType[] values() {
        return (PlacementType[]) $VALUES.clone();
    }
}
