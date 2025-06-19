package com.braze.enums.inappmessage;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class ImageStyle {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ ImageStyle[] $VALUES;
    public static final ImageStyle GRAPHIC = new ImageStyle("GRAPHIC", 0);
    public static final ImageStyle TOP = new ImageStyle("TOP", 1);

    private static final /* synthetic */ ImageStyle[] $values() {
        return new ImageStyle[]{GRAPHIC, TOP};
    }

    static {
        ImageStyle[] imageStyleArr$values = $values();
        $VALUES = imageStyleArr$values;
        $ENTRIES = AbstractC3328d.f(imageStyleArr$values);
    }

    private ImageStyle(String str, int i) {
    }

    public static ImageStyle valueOf(String str) {
        return (ImageStyle) Enum.valueOf(ImageStyle.class, str);
    }

    public static ImageStyle[] values() {
        return (ImageStyle[]) $VALUES.clone();
    }
}
