package com.quizlet.utm.mediums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a implements com.quizlet.utm.b {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ a[] $VALUES;
    public static final a SHARE_LINK = new a("SHARE_LINK", 0, 1);
    private final int index;

    private static final /* synthetic */ a[] $values() {
        return new a[]{SHARE_LINK};
    }

    static {
        a[] aVarArr$values = $values();
        $VALUES = aVarArr$values;
        $ENTRIES = AbstractC3328d.f(aVarArr$values);
    }

    private a(String str, int i, int i2) {
        this.index = i2;
    }

    @NotNull
    public static kotlin.enums.a getEntries() {
        return $ENTRIES;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) $VALUES.clone();
    }

    @Override // com.quizlet.utm.b
    public int getIndex() {
        return this.index;
    }
}
