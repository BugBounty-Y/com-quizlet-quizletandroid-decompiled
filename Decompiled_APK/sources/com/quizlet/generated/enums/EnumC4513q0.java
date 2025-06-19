package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.generated.enums.q0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4513q0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ EnumC4513q0[] $VALUES;

    @NotNull
    public static final C4510p0 Companion;
    public static final EnumC4513q0 FLASHCARDS_COMPLETION_FLOW;
    public static final EnumC4513q0 LEARN_COMPLETION_FLOW;
    public static final EnumC4513q0 MATCH_COMPLETION_FLOW;
    public static final EnumC4513q0 TEST_MODE_FLOW;
    public static final EnumC4513q0 TEST_PREVIEW_PAGE;
    public static final EnumC4513q0 TEST_RESULTS_PAGE;
    public static final EnumC4513q0 TEST_SETUP_MODAL;

    @NotNull
    private final String value;

    static {
        EnumC4513q0 enumC4513q0 = new EnumC4513q0("TEST_PREVIEW_PAGE", 0, "test_preview_page");
        TEST_PREVIEW_PAGE = enumC4513q0;
        EnumC4513q0 enumC4513q02 = new EnumC4513q0("TEST_MODE_FLOW", 1, "test_mode_flow");
        TEST_MODE_FLOW = enumC4513q02;
        EnumC4513q0 enumC4513q03 = new EnumC4513q0("TEST_RESULTS_PAGE", 2, "test_results_page");
        TEST_RESULTS_PAGE = enumC4513q03;
        EnumC4513q0 enumC4513q04 = new EnumC4513q0("TEST_SETUP_MODAL", 3, "test_setup_modal");
        TEST_SETUP_MODAL = enumC4513q04;
        EnumC4513q0 enumC4513q05 = new EnumC4513q0("LEARN_COMPLETION_FLOW", 4, "learn_completion_flow");
        LEARN_COMPLETION_FLOW = enumC4513q05;
        EnumC4513q0 enumC4513q06 = new EnumC4513q0("FLASHCARDS_COMPLETION_FLOW", 5, "flashcards_completion_flow");
        FLASHCARDS_COMPLETION_FLOW = enumC4513q06;
        EnumC4513q0 enumC4513q07 = new EnumC4513q0("MATCH_COMPLETION_FLOW", 6, "match_completion_flow");
        MATCH_COMPLETION_FLOW = enumC4513q07;
        EnumC4513q0[] enumC4513q0Arr = {enumC4513q0, enumC4513q02, enumC4513q03, enumC4513q04, enumC4513q05, enumC4513q06, enumC4513q07};
        $VALUES = enumC4513q0Arr;
        $ENTRIES = AbstractC3328d.f(enumC4513q0Arr);
        Companion = new C4510p0();
    }

    public EnumC4513q0(String str, int i, String str2) {
        this.value = str2;
    }

    public static EnumC4513q0 valueOf(String str) {
        return (EnumC4513q0) Enum.valueOf(EnumC4513q0.class, str);
    }

    public static EnumC4513q0[] values() {
        return (EnumC4513q0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
