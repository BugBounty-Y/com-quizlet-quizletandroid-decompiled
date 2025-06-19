package com.quizlet.quizletandroid.ui.library.helper;

import com.quizlet.data.model.Y1;
import com.quizlet.generated.enums.EnumC4534z;

/* loaded from: classes3.dex */
public abstract /* synthetic */ class a {
    public static final /* synthetic */ int[] a;

    static {
        int[] iArr = new int[Y1.values().length];
        try {
            iArr[0] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            Y1 y1 = Y1.a;
            iArr[1] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            Y1 y12 = Y1.a;
            iArr[2] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            Y1 y13 = Y1.a;
            iArr[3] = 4;
        } catch (NoSuchFieldError unused4) {
        }
        int[] iArr2 = new int[EnumC4534z.values().length];
        try {
            iArr2[EnumC4534z.PDF.ordinal()] = 1;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            iArr2[EnumC4534z.PPTX.ordinal()] = 2;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            iArr2[EnumC4534z.DOCX.ordinal()] = 3;
        } catch (NoSuchFieldError unused7) {
        }
        try {
            iArr2[EnumC4534z.GOOGLE_SLIDES.ordinal()] = 4;
        } catch (NoSuchFieldError unused8) {
        }
        try {
            iArr2[EnumC4534z.GOOGLE_DOC.ordinal()] = 5;
        } catch (NoSuchFieldError unused9) {
        }
        try {
            iArr2[EnumC4534z.TEXT.ordinal()] = 6;
        } catch (NoSuchFieldError unused10) {
        }
        try {
            iArr2[EnumC4534z.FLASHCARD_SET.ordinal()] = 7;
        } catch (NoSuchFieldError unused11) {
        }
        try {
            iArr2[EnumC4534z.YOUTUBE.ordinal()] = 8;
        } catch (NoSuchFieldError unused12) {
        }
        try {
            iArr2[EnumC4534z.MARKDOWN.ordinal()] = 9;
        } catch (NoSuchFieldError unused13) {
        }
        try {
            iArr2[EnumC4534z.OCR.ordinal()] = 10;
        } catch (NoSuchFieldError unused14) {
        }
        try {
            iArr2[EnumC4534z.CSV.ordinal()] = 11;
        } catch (NoSuchFieldError unused15) {
        }
        a = iArr2;
    }
}
