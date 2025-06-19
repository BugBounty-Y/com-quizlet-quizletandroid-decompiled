package com.quizlet.ui.compose;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.ui.compose.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4819l {
    public static final EnumC4819l a;
    public static final EnumC4819l b;
    public static final /* synthetic */ EnumC4819l[] c;

    static {
        EnumC4819l enumC4819l = new EnumC4819l("VERTICAL", 0);
        a = enumC4819l;
        EnumC4819l enumC4819l2 = new EnumC4819l("HORIZONTAL", 1);
        b = enumC4819l2;
        EnumC4819l[] enumC4819lArr = {enumC4819l, enumC4819l2};
        c = enumC4819lArr;
        AbstractC3328d.f(enumC4819lArr);
    }

    public static EnumC4819l valueOf(String str) {
        return (EnumC4819l) Enum.valueOf(EnumC4819l.class, str);
    }

    public static EnumC4819l[] values() {
        return (EnumC4819l[]) c.clone();
    }
}
