package com.braze.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class LocationProviderName {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ LocationProviderName[] $VALUES;
    public static final LocationProviderName GPS = new LocationProviderName("GPS", 0);
    public static final LocationProviderName NETWORK = new LocationProviderName("NETWORK", 1);
    public static final LocationProviderName PASSIVE = new LocationProviderName("PASSIVE", 2);

    private static final /* synthetic */ LocationProviderName[] $values() {
        return new LocationProviderName[]{GPS, NETWORK, PASSIVE};
    }

    static {
        LocationProviderName[] locationProviderNameArr$values = $values();
        $VALUES = locationProviderNameArr$values;
        $ENTRIES = AbstractC3328d.f(locationProviderNameArr$values);
    }

    private LocationProviderName(String str, int i) {
    }

    public static LocationProviderName valueOf(String str) {
        return (LocationProviderName) Enum.valueOf(LocationProviderName.class, str);
    }

    public static LocationProviderName[] values() {
        return (LocationProviderName[]) $VALUES.clone();
    }
}
