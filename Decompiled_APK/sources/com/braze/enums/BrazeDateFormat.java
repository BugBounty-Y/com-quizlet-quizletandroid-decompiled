package com.braze.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class BrazeDateFormat {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ BrazeDateFormat[] $VALUES;
    private final String format;
    public static final BrazeDateFormat SHORT = new BrazeDateFormat("SHORT", 0, "yyyy-MM-dd");
    public static final BrazeDateFormat LONG = new BrazeDateFormat("LONG", 1, "yyyy-MM-dd kk:mm:ss");
    public static final BrazeDateFormat ANDROID_LOGCAT = new BrazeDateFormat("ANDROID_LOGCAT", 2, "MM-dd kk:mm:ss.SSS");
    public static final BrazeDateFormat CLOCK_12_HOUR = new BrazeDateFormat("CLOCK_12_HOUR", 3, "h:mm a");

    private static final /* synthetic */ BrazeDateFormat[] $values() {
        return new BrazeDateFormat[]{SHORT, LONG, ANDROID_LOGCAT, CLOCK_12_HOUR};
    }

    static {
        BrazeDateFormat[] brazeDateFormatArr$values = $values();
        $VALUES = brazeDateFormatArr$values;
        $ENTRIES = AbstractC3328d.f(brazeDateFormatArr$values);
    }

    private BrazeDateFormat(String str, int i, String str2) {
        this.format = str2;
    }

    public static BrazeDateFormat valueOf(String str) {
        return (BrazeDateFormat) Enum.valueOf(BrazeDateFormat.class, str);
    }

    public static BrazeDateFormat[] values() {
        return (BrazeDateFormat[]) $VALUES.clone();
    }

    public final String getFormat() {
        return this.format;
    }
}
