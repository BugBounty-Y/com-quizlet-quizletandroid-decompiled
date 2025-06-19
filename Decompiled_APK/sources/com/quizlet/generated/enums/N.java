package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class N {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ N[] $VALUES;
    public static final N AUDIO;

    @NotNull
    public static final M Companion;
    public static final N DIAGRAM_SHAPE;
    public static final N IMAGE;
    public static final N TEXT;
    public static final N VIDEO;
    private final int value;

    static {
        N n = new N("TEXT", 0, 1);
        TEXT = n;
        N n2 = new N("IMAGE", 1, 2);
        IMAGE = n2;
        N n3 = new N("VIDEO", 2, 3);
        VIDEO = n3;
        N n4 = new N("AUDIO", 3, 4);
        AUDIO = n4;
        N n5 = new N("DIAGRAM_SHAPE", 4, 5);
        DIAGRAM_SHAPE = n5;
        N[] nArr = {n, n2, n3, n4, n5};
        $VALUES = nArr;
        $ENTRIES = AbstractC3328d.f(nArr);
        Companion = new M();
    }

    public N(String str, int i, int i2) {
        this.value = i2;
    }

    public static N valueOf(String str) {
        return (N) Enum.valueOf(N.class, str);
    }

    public static N[] values() {
        return (N[]) $VALUES.clone();
    }
}
