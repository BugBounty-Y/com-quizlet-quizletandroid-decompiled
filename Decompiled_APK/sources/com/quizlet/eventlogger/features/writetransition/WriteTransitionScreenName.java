package com.quizlet.eventlogger.features.writetransition;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes2.dex */
public final class WriteTransitionScreenName {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ WriteTransitionScreenName[] $VALUES;
    public static final WriteTransitionScreenName a;

    @NotNull
    private final String value;

    static {
        WriteTransitionScreenName writeTransitionScreenName = new WriteTransitionScreenName("LEARN_GOAL_INTAKE_SCREEN", 0, "learn_goal_intake_screen");
        WriteTransitionScreenName writeTransitionScreenName2 = new WriteTransitionScreenName("LEARN_KNOWLEDGE_INTAKE_SCREEN", 1, "learn_knowledge_intake_screen");
        WriteTransitionScreenName writeTransitionScreenName3 = new WriteTransitionScreenName("LEARN_OPTIONS_MODAL", 2, "learn_options_modal");
        a = writeTransitionScreenName3;
        WriteTransitionScreenName[] writeTransitionScreenNameArr = {writeTransitionScreenName, writeTransitionScreenName2, writeTransitionScreenName3};
        $VALUES = writeTransitionScreenNameArr;
        $ENTRIES = AbstractC3328d.f(writeTransitionScreenNameArr);
    }

    private WriteTransitionScreenName(String str, int i, String str2) {
        this.value = str2;
    }

    @NotNull
    public static a getEntries() {
        return $ENTRIES;
    }

    public static WriteTransitionScreenName valueOf(String str) {
        return (WriteTransitionScreenName) Enum.valueOf(WriteTransitionScreenName.class, str);
    }

    public static WriteTransitionScreenName[] values() {
        return (WriteTransitionScreenName[]) $VALUES.clone();
    }

    @NotNull
    public final String getValue() {
        return this.value;
    }
}
