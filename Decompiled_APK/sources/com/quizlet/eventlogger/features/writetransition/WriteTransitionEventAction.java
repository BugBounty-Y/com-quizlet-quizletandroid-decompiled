package com.quizlet.eventlogger.features.writetransition;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.enums.a;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes2.dex */
public final class WriteTransitionEventAction {
    private static final /* synthetic */ a $ENTRIES;
    private static final /* synthetic */ WriteTransitionEventAction[] $VALUES;
    public static final WriteTransitionEventAction a;

    @NotNull
    private final String value;

    static {
        WriteTransitionEventAction writeTransitionEventAction = new WriteTransitionEventAction("STUDY_MODE_BUTTON_CLICKED", 0, "study_mode_button_clicked");
        a = writeTransitionEventAction;
        WriteTransitionEventAction[] writeTransitionEventActionArr = {writeTransitionEventAction};
        $VALUES = writeTransitionEventActionArr;
        $ENTRIES = AbstractC3328d.f(writeTransitionEventActionArr);
    }

    private WriteTransitionEventAction(String str, int i, String str2) {
        this.value = str2;
    }

    @NotNull
    public static a getEntries() {
        return $ENTRIES;
    }

    public static WriteTransitionEventAction valueOf(String str) {
        return (WriteTransitionEventAction) Enum.valueOf(WriteTransitionEventAction.class, str);
    }

    public static WriteTransitionEventAction[] values() {
        return (WriteTransitionEventAction[]) $VALUES.clone();
    }

    @NotNull
    public final String getValue() {
        return this.value;
    }
}
