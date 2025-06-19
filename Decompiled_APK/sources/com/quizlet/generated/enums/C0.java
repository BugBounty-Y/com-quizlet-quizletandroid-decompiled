package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class C0 {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ C0[] $VALUES;
    public static final C0 ALL_AT_ONCE;

    @NotNull
    public static final B0 Companion;
    public static final C0 ONE_BY_ONE;

    @NotNull
    private final String value;

    static {
        C0 c0 = new C0("ALL_AT_ONCE", 0, "all_at_once");
        ALL_AT_ONCE = c0;
        C0 c02 = new C0("ONE_BY_ONE", 1, "one_by_one");
        ONE_BY_ONE = c02;
        C0[] c0Arr = {c0, c02};
        $VALUES = c0Arr;
        $ENTRIES = AbstractC3328d.f(c0Arr);
        Companion = new B0();
    }

    public C0(String str, int i, String str2) {
        this.value = str2;
    }

    public static C0 valueOf(String str) {
        return (C0) Enum.valueOf(C0.class, str);
    }

    public static C0[] values() {
        return (C0[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
