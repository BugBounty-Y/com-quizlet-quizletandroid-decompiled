package com.quizlet.generated.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class U {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ U[] $VALUES;
    public static final U CLICK;

    @NotNull
    public static final T Companion;
    public static final U SHOW;

    @NotNull
    private final String value;

    static {
        U u = new U("CLICK", 0, "click");
        CLICK = u;
        U u2 = new U("SHOW", 1, "show");
        SHOW = u2;
        U[] uArr = {u, u2};
        $VALUES = uArr;
        $ENTRIES = AbstractC3328d.f(uArr);
        Companion = new T();
    }

    public U(String str, int i, String str2) {
        this.value = str2;
    }

    public static U valueOf(String str) {
        return (U) Enum.valueOf(U.class, str);
    }

    public static U[] values() {
        return (U[]) $VALUES.clone();
    }

    public final String a() {
        return this.value;
    }
}
