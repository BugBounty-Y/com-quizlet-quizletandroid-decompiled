package com.quizlet.shared.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f
/* loaded from: classes3.dex */
public final class u implements serialization.b {

    @NotNull
    public static final UserUpgradeType$Companion Companion;
    public static final Object b;
    public static final /* synthetic */ u[] c;
    public final int a;

    static {
        u[] uVarArr = {new u("NO_UPGRADE", 0, 0), new u("PLUS", 1, 1), new u("TEACHER", 2, 2), new u("GO", 3, 3)};
        c = uVarArr;
        AbstractC3328d.f(uVarArr);
        Companion = new UserUpgradeType$Companion();
        b = kotlin.l.a(kotlin.m.b, i.c);
    }

    public u(String str, int i, int i2) {
        this.a = i2;
    }

    public static u valueOf(String str) {
        return (u) Enum.valueOf(u.class, str);
    }

    public static u[] values() {
        return (u[]) c.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
