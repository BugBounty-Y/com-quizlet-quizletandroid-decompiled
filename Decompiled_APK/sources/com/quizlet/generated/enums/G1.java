package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class G1 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ G1[] $VALUES;

    @NotNull
    public static final F1 Companion;
    public static final G1 FOLDER;
    public static final G1 PREP_PACK;
    public static final G1 SET;
    private final int value;

    static {
        G1 g1 = new G1("SET", 0, 1);
        SET = g1;
        G1 g12 = new G1("FOLDER", 1, 2);
        FOLDER = g12;
        G1 g13 = new G1("PREP_PACK", 2, 3);
        PREP_PACK = g13;
        G1[] g1Arr = {g1, g12, g13};
        $VALUES = g1Arr;
        $ENTRIES = AbstractC3328d.f(g1Arr);
        Companion = new F1();
    }

    public G1(String str, int i, int i2) {
        this.value = i2;
    }

    public static final G1 a(Integer num) {
        Companion.getClass();
        for (G1 g1 : values()) {
            if (g1.value == num.intValue()) {
                return g1;
            }
        }
        return null;
    }

    public static G1 valueOf(String str) {
        return (G1) Enum.valueOf(G1.class, str);
    }

    public static G1[] values() {
        return (G1[]) $VALUES.clone();
    }

    public final int b() {
        return this.value;
    }
}
