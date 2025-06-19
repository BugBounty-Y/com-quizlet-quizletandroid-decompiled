package com.quizlet.learn.logging;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class c {
    public static final /* synthetic */ c[] a;

    static {
        c[] cVarArr = {new c("STUDY_ALL_TERMS", 0), new c("TAKE_A_NEW_TEST", 1), new c("REVIEW_FLASHCARDS", 2)};
        a = cVarArr;
        AbstractC3328d.f(cVarArr);
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) a.clone();
    }
}
