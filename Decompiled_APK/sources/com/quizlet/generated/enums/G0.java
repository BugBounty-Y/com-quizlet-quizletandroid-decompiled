package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class G0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ G0[] $VALUES;
    public static final G0 ADD_DIAGRAMS;
    public static final G0 ADD_SHAPES_TO_DIAGRAM;
    public static final G0 AD_FREE;
    public static final G0 AUDIO_RECORDING;
    public static final G0 CLASS_PROGRESS;
    public static final G0 CUSTOM_MCQS;

    @NotNull
    public static final F0 Companion;
    public static final G0 EXPLANATION_QUESTION;
    public static final G0 IMAGE_UPLOAD;
    public static final G0 LEARN_MODE;
    public static final G0 PRACTICE_TEST_CONSUMPTION;
    public static final G0 PRACTICE_TEST_UPLOAD;
    public static final G0 QCHAT;
    public static final G0 RICH_TEXT;
    public static final G0 STUDY_GUIDE_UPLOAD;
    public static final G0 TEST_MODE;
    public static final G0 TEXTBOOK_EXERCISE;

    @NotNull
    private final String value;

    static {
        G0 g0 = new G0("AD_FREE", 0, "ad_free");
        AD_FREE = g0;
        G0 g02 = new G0("ADD_DIAGRAMS", 1, "add_diagrams");
        ADD_DIAGRAMS = g02;
        G0 g03 = new G0("ADD_SHAPES_TO_DIAGRAM", 2, "add_shapes_to_diagram");
        ADD_SHAPES_TO_DIAGRAM = g03;
        G0 g04 = new G0("AUDIO_RECORDING", 3, "audio_recording");
        AUDIO_RECORDING = g04;
        G0 g05 = new G0("CLASS_PROGRESS", 4, "class_progress");
        CLASS_PROGRESS = g05;
        G0 g06 = new G0("CUSTOM_MCQS", 5, "custom_mcqs");
        CUSTOM_MCQS = g06;
        G0 g07 = new G0("EXPLANATION_QUESTION", 6, "explanation_question");
        EXPLANATION_QUESTION = g07;
        G0 g08 = new G0("IMAGE_UPLOAD", 7, "image_upload");
        IMAGE_UPLOAD = g08;
        G0 g09 = new G0("LEARN_MODE", 8, "learn_mode");
        LEARN_MODE = g09;
        G0 g010 = new G0("PRACTICE_TEST_CONSUMPTION", 9, "practice_test_consumption");
        PRACTICE_TEST_CONSUMPTION = g010;
        G0 g011 = new G0("PRACTICE_TEST_UPLOAD", 10, "practice_test_upload");
        PRACTICE_TEST_UPLOAD = g011;
        G0 g012 = new G0("QCHAT", 11, "qchat");
        QCHAT = g012;
        G0 g013 = new G0("RICH_TEXT", 12, "rich_text");
        RICH_TEXT = g013;
        G0 g014 = new G0("STUDY_GUIDE_UPLOAD", 13, "study_guide_upload");
        STUDY_GUIDE_UPLOAD = g014;
        G0 g015 = new G0("TEST_MODE", 14, "test_mode");
        TEST_MODE = g015;
        G0 g016 = new G0("TEXTBOOK_EXERCISE", 15, "textbook_exercise");
        TEXTBOOK_EXERCISE = g016;
        G0[] g0Arr = {g0, g02, g03, g04, g05, g06, g07, g08, g09, g010, g011, g012, g013, g014, g015, g016};
        $VALUES = g0Arr;
        $ENTRIES = AbstractC3328d.f(g0Arr);
        Companion = new F0();
    }

    public G0(String str, int i, String str2) {
        this.value = str2;
    }

    public static G0 valueOf(String str) {
        return (G0) Enum.valueOf(G0.class, str);
    }

    public static G0[] values() {
        return (G0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
