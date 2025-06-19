package com.quizlet.shared.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = s.class)
/* loaded from: classes3.dex */
public final class t implements serialization.f {

    @NotNull
    public static final UndoableFlashcardAction$Companion Companion;
    public static final t b;
    public static final t c;
    public static final /* synthetic */ t[] d;
    public final String a;

    static {
        t tVar = new t("MOVE_FLASHCARD_TO_NEXT_ROUND", 0, "MOVE_FLASHCARD_TO_NEXT_ROUND");
        b = tVar;
        t tVar2 = new t("REMOVE_FLASHCARD", 1, "REMOVE_FLASHCARD");
        c = tVar2;
        t[] tVarArr = {tVar, tVar2};
        d = tVarArr;
        AbstractC3328d.f(tVarArr);
        Companion = new UndoableFlashcardAction$Companion();
    }

    public t(String str, int i, String str2) {
        this.a = str2;
    }

    public static t valueOf(String str) {
        return (t) Enum.valueOf(t.class, str);
    }

    public static t[] values() {
        return (t[]) d.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
