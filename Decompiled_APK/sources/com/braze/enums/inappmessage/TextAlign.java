package com.braze.enums.inappmessage;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class TextAlign {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ TextAlign[] $VALUES;
    public static final TextAlign START = new TextAlign("START", 0);
    public static final TextAlign CENTER = new TextAlign("CENTER", 1);
    public static final TextAlign END = new TextAlign("END", 2);

    private static final /* synthetic */ TextAlign[] $values() {
        return new TextAlign[]{START, CENTER, END};
    }

    static {
        TextAlign[] textAlignArr$values = $values();
        $VALUES = textAlignArr$values;
        $ENTRIES = AbstractC3328d.f(textAlignArr$values);
    }

    private TextAlign(String str, int i) {
    }

    public static TextAlign valueOf(String str) {
        return (TextAlign) Enum.valueOf(TextAlign.class, str);
    }

    public static TextAlign[] values() {
        return (TextAlign[]) $VALUES.clone();
    }
}
