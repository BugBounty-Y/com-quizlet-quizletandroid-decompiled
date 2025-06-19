package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class E0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ E0[] $VALUES;

    @NotNull
    public static final D0 Companion;
    public static final E0 EXPERT_CREATOR_FLOW;
    public static final E0 FLASHCARDS_COMPLETION_FLOW;
    public static final E0 LEARN_COMPLETION_FLOW;
    public static final E0 MATCH_COMPLETION_FLOW;
    public static final E0 TEST_MODE_FLOW;
    public static final E0 TRIVIA_CAMPAIGN;
    public static final E0 UPLOAD_PAGE;

    @NotNull
    private final String value;

    static {
        E0 e0 = new E0("UPLOAD_PAGE", 0, "upload_page");
        UPLOAD_PAGE = e0;
        E0 e02 = new E0("TEST_MODE_FLOW", 1, "test_mode_flow");
        TEST_MODE_FLOW = e02;
        E0 e03 = new E0("EXPERT_CREATOR_FLOW", 2, "expert_creator_flow");
        EXPERT_CREATOR_FLOW = e03;
        E0 e04 = new E0("LEARN_COMPLETION_FLOW", 3, "learn_completion_flow");
        LEARN_COMPLETION_FLOW = e04;
        E0 e05 = new E0("FLASHCARDS_COMPLETION_FLOW", 4, "flashcards_completion_flow");
        FLASHCARDS_COMPLETION_FLOW = e05;
        E0 e06 = new E0("MATCH_COMPLETION_FLOW", 5, "match_completion_flow");
        MATCH_COMPLETION_FLOW = e06;
        E0 e07 = new E0("TRIVIA_CAMPAIGN", 6, "trivia_campaign");
        TRIVIA_CAMPAIGN = e07;
        E0[] e0Arr = {e0, e02, e03, e04, e05, e06, e07};
        $VALUES = e0Arr;
        $ENTRIES = AbstractC3328d.f(e0Arr);
        Companion = new D0();
    }

    public E0(String str, int i, String str2) {
        this.value = str2;
    }

    public static E0 valueOf(String str) {
        return (E0) Enum.valueOf(E0.class, str);
    }

    public static E0[] values() {
        return (E0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
