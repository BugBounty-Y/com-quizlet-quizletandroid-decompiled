package com.braze.enums;

import com.amazon.device.ads.DtbDeviceData;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class DeviceKey {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ DeviceKey[] $VALUES;
    private final String key;
    public static final DeviceKey ANDROID_VERSION = new DeviceKey("ANDROID_VERSION", 0, "os_version");
    public static final DeviceKey CARRIER = new DeviceKey("CARRIER", 1, "carrier");
    public static final DeviceKey BRAND = new DeviceKey("BRAND", 2, "brand");
    public static final DeviceKey MODEL = new DeviceKey("MODEL", 3, DtbDeviceData.DEVICE_DATA_MODEL_KEY);
    public static final DeviceKey RESOLUTION = new DeviceKey("RESOLUTION", 4, "resolution");
    public static final DeviceKey LOCALE = new DeviceKey("LOCALE", 5, "locale");
    public static final DeviceKey TIMEZONE = new DeviceKey("TIMEZONE", 6, "time_zone");
    public static final DeviceKey NOTIFICATIONS_ENABLED = new DeviceKey("NOTIFICATIONS_ENABLED", 7, "remote_notification_enabled");
    public static final DeviceKey IS_BACKGROUND_RESTRICTED = new DeviceKey("IS_BACKGROUND_RESTRICTED", 8, "android_is_background_restricted");
    public static final DeviceKey GOOGLE_ADVERTISING_ID = new DeviceKey("GOOGLE_ADVERTISING_ID", 9, "google_ad_id");
    public static final DeviceKey AD_TRACKING_ENABLED = new DeviceKey("AD_TRACKING_ENABLED", 10, "ad_tracking_enabled");

    private static final /* synthetic */ DeviceKey[] $values() {
        return new DeviceKey[]{ANDROID_VERSION, CARRIER, BRAND, MODEL, RESOLUTION, LOCALE, TIMEZONE, NOTIFICATIONS_ENABLED, IS_BACKGROUND_RESTRICTED, GOOGLE_ADVERTISING_ID, AD_TRACKING_ENABLED};
    }

    static {
        DeviceKey[] deviceKeyArr$values = $values();
        $VALUES = deviceKeyArr$values;
        $ENTRIES = AbstractC3328d.f(deviceKeyArr$values);
    }

    private DeviceKey(String str, int i, String str2) {
        this.key = str2;
    }

    public static DeviceKey valueOf(String str) {
        return (DeviceKey) Enum.valueOf(DeviceKey.class, str);
    }

    public static DeviceKey[] values() {
        return (DeviceKey[]) $VALUES.clone();
    }

    public final String getKey() {
        return this.key;
    }
}
