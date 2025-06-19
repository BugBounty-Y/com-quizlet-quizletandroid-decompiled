package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.g0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4483g0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4483g0[] $VALUES;
    public static final EnumC4483g0 AUDIO;
    public static final EnumC4483g0 CAMERA;

    @NotNull
    public static final C4480f0 Companion;
    public static final EnumC4483g0 FILE;
    public static final EnumC4483g0 FLASHCARD_SET;
    public static final EnumC4483g0 GDOC;
    public static final EnumC4483g0 IMAGE;
    public static final EnumC4483g0 MARKDOWN;
    public static final EnumC4483g0 TEXT;
    public static final EnumC4483g0 YOUTUBE;

    @NotNull
    private final String value;

    static {
        EnumC4483g0 enumC4483g0 = new EnumC4483g0("AUDIO", 0, "audio");
        AUDIO = enumC4483g0;
        EnumC4483g0 enumC4483g02 = new EnumC4483g0("CAMERA", 1, "camera");
        CAMERA = enumC4483g02;
        EnumC4483g0 enumC4483g03 = new EnumC4483g0("FILE", 2, "file");
        FILE = enumC4483g03;
        EnumC4483g0 enumC4483g04 = new EnumC4483g0("FLASHCARD_SET", 3, "flashcard_set");
        FLASHCARD_SET = enumC4483g04;
        EnumC4483g0 enumC4483g05 = new EnumC4483g0("IMAGE", 4, "image");
        IMAGE = enumC4483g05;
        EnumC4483g0 enumC4483g06 = new EnumC4483g0("TEXT", 5, "text");
        TEXT = enumC4483g06;
        EnumC4483g0 enumC4483g07 = new EnumC4483g0("GDOC", 6, "gdoc");
        GDOC = enumC4483g07;
        EnumC4483g0 enumC4483g08 = new EnumC4483g0("YOUTUBE", 7, "youtube");
        YOUTUBE = enumC4483g08;
        EnumC4483g0 enumC4483g09 = new EnumC4483g0("MARKDOWN", 8, "markdown");
        MARKDOWN = enumC4483g09;
        EnumC4483g0[] enumC4483g0Arr = {enumC4483g0, enumC4483g02, enumC4483g03, enumC4483g04, enumC4483g05, enumC4483g06, enumC4483g07, enumC4483g08, enumC4483g09};
        $VALUES = enumC4483g0Arr;
        $ENTRIES = AbstractC3328d.f(enumC4483g0Arr);
        Companion = new C4480f0();
    }

    public EnumC4483g0(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4483g0 valueOf(String str) {
        return (EnumC4483g0) Enum.valueOf(EnumC4483g0.class, str);
    }

    public static EnumC4483g0[] values() {
        return (EnumC4483g0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
