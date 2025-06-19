package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.z, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4534z {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4534z[] $VALUES;
    public static final EnumC4534z CSV;

    @NotNull
    public static final C4532y Companion;
    public static final EnumC4534z DOCX;
    public static final EnumC4534z FLASHCARD_SET;
    public static final EnumC4534z GOOGLE_DOC;
    public static final EnumC4534z GOOGLE_SLIDES;
    public static final EnumC4534z MARKDOWN;
    public static final EnumC4534z OCR;
    public static final EnumC4534z PDF;
    public static final EnumC4534z PPTX;
    public static final EnumC4534z TEXT;
    public static final EnumC4534z YOUTUBE;

    @NotNull
    private final String value;

    static {
        EnumC4534z enumC4534z = new EnumC4534z("DOCX", 0, "docx");
        DOCX = enumC4534z;
        EnumC4534z enumC4534z2 = new EnumC4534z("GOOGLE_DOC", 1, "gdoc");
        GOOGLE_DOC = enumC4534z2;
        EnumC4534z enumC4534z3 = new EnumC4534z("GOOGLE_SLIDES", 2, "gslides");
        GOOGLE_SLIDES = enumC4534z3;
        EnumC4534z enumC4534z4 = new EnumC4534z("PDF", 3, "pdf");
        PDF = enumC4534z4;
        EnumC4534z enumC4534z5 = new EnumC4534z("PPTX", 4, "pptx");
        PPTX = enumC4534z5;
        EnumC4534z enumC4534z6 = new EnumC4534z("TEXT", 5, "text");
        TEXT = enumC4534z6;
        EnumC4534z enumC4534z7 = new EnumC4534z("YOUTUBE", 6, "youtube");
        YOUTUBE = enumC4534z7;
        EnumC4534z enumC4534z8 = new EnumC4534z("OCR", 7, "ocr");
        OCR = enumC4534z8;
        EnumC4534z enumC4534z9 = new EnumC4534z("FLASHCARD_SET", 8, "flashcard_set");
        FLASHCARD_SET = enumC4534z9;
        EnumC4534z enumC4534z10 = new EnumC4534z("CSV", 9, "csv");
        CSV = enumC4534z10;
        EnumC4534z enumC4534z11 = new EnumC4534z("MARKDOWN", 10, "markdown");
        MARKDOWN = enumC4534z11;
        EnumC4534z[] enumC4534zArr = {enumC4534z, enumC4534z2, enumC4534z3, enumC4534z4, enumC4534z5, enumC4534z6, enumC4534z7, enumC4534z8, enumC4534z9, enumC4534z10, enumC4534z11};
        $VALUES = enumC4534zArr;
        $ENTRIES = AbstractC3328d.f(enumC4534zArr);
        Companion = new C4532y();
    }

    public EnumC4534z(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4534z valueOf(String str) {
        return (EnumC4534z) Enum.valueOf(EnumC4534z.class, str);
    }

    public static EnumC4534z[] values() {
        return (EnumC4534z[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
