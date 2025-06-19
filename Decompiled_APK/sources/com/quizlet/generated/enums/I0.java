package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class I0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ I0[] $VALUES;
    public static final I0 BLAST_SINGLE_PLAYER;
    public static final I0 BLOCKS;

    @NotNull
    public static final H0 Companion;
    public static final I0 LEARN_MOBILE_NATIVE_IMPROVEMENTS;
    public static final I0 MAGIC_NOTES;
    public static final I0 PRACTICE_TESTS_CAN_TAKE_TEST;
    public static final I0 PRACTICE_TESTS_CAN_UPLOAD_DOCUMENT;
    public static final I0 PRACTICE_TESTS_CAN_VIEW_TEST_PREVIEW;
    public static final I0 PRACTICE_TESTS_CAN_VIEW_TEST_PREVIEW_AND_TAKE_TEST;
    public static final I0 QCHAT;
    public static final I0 STUDY_HUB;

    @NotNull
    private final String value;

    static {
        I0 i0 = new I0("BLAST_SINGLE_PLAYER", 0, "blast_single_player");
        BLAST_SINGLE_PLAYER = i0;
        I0 i02 = new I0("BLOCKS", 1, "blocks");
        BLOCKS = i02;
        I0 i03 = new I0("LEARN_MOBILE_NATIVE_IMPROVEMENTS", 2, "learn_mobile_native_improvements");
        LEARN_MOBILE_NATIVE_IMPROVEMENTS = i03;
        I0 i04 = new I0("MAGIC_NOTES", 3, "magic_notes");
        MAGIC_NOTES = i04;
        I0 i05 = new I0("PRACTICE_TESTS_CAN_TAKE_TEST", 4, "practice_tests_can_take_test");
        PRACTICE_TESTS_CAN_TAKE_TEST = i05;
        I0 i06 = new I0("PRACTICE_TESTS_CAN_UPLOAD_DOCUMENT", 5, "practice_tests_can_upload_document");
        PRACTICE_TESTS_CAN_UPLOAD_DOCUMENT = i06;
        I0 i07 = new I0("PRACTICE_TESTS_CAN_VIEW_TEST_PREVIEW", 6, "practice_tests_can_view_test_preview");
        PRACTICE_TESTS_CAN_VIEW_TEST_PREVIEW = i07;
        I0 i08 = new I0("PRACTICE_TESTS_CAN_VIEW_TEST_PREVIEW_AND_TAKE_TEST", 7, "practice_tests_can_view_test_preview_and_take_test");
        PRACTICE_TESTS_CAN_VIEW_TEST_PREVIEW_AND_TAKE_TEST = i08;
        I0 i09 = new I0("QCHAT", 8, "qchat");
        QCHAT = i09;
        I0 i010 = new I0("STUDY_HUB", 9, "study_hub");
        STUDY_HUB = i010;
        I0[] i0Arr = {i0, i02, i03, i04, i05, i06, i07, i08, i09, i010};
        $VALUES = i0Arr;
        $ENTRIES = AbstractC3328d.f(i0Arr);
        Companion = new H0();
    }

    public I0(String str, int i, String str2) {
        this.value = str2;
    }

    public static I0 valueOf(String str) {
        return (I0) Enum.valueOf(I0.class, str);
    }

    public static I0[] values() {
        return (I0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
