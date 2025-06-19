package com.braze.enums.inappmessage;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class CropType {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ CropType[] $VALUES;
    public static final CropType FIT_CENTER = new CropType("FIT_CENTER", 0);
    public static final CropType CENTER_CROP = new CropType("CENTER_CROP", 1);

    private static final /* synthetic */ CropType[] $values() {
        return new CropType[]{FIT_CENTER, CENTER_CROP};
    }

    static {
        CropType[] cropTypeArr$values = $values();
        $VALUES = cropTypeArr$values;
        $ENTRIES = AbstractC3328d.f(cropTypeArr$values);
    }

    private CropType(String str, int i) {
    }

    public static CropType valueOf(String str) {
        return (CropType) Enum.valueOf(CropType.class, str);
    }

    public static CropType[] values() {
        return (CropType[]) $VALUES.clone();
    }
}
