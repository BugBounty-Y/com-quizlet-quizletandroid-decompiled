package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class Y {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ Y[] $VALUES;
    public static final Y QUESTION;
    public static final Y TEXTBOOK;
    public static final Y TEXTBOOK_EXERCISE;

    @NotNull
    private final String filter;

    static {
        Y y = new Y("TEXTBOOK", 0, "textbook");
        TEXTBOOK = y;
        Y y2 = new Y("QUESTION", 1, "question");
        QUESTION = y2;
        Y y3 = new Y("TEXTBOOK_EXERCISE", 2, "textbook_exercise");
        TEXTBOOK_EXERCISE = y3;
        Y[] yArr = {y, y2, y3};
        $VALUES = yArr;
        $ENTRIES = AbstractC3328d.f(yArr);
    }

    public Y(String str, int i, String str2) {
        this.filter = str2;
    }

    public static kotlin.enums.a a() {
        return $ENTRIES;
    }

    public static Y valueOf(String str) {
        return (Y) Enum.valueOf(Y.class, str);
    }

    public static Y[] values() {
        return (Y[]) $VALUES.clone();
    }

    public final String b() {
        return this.filter;
    }
}
