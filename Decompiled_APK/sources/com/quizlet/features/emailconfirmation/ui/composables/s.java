package com.quizlet.features.emailconfirmation.ui.composables;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class s {
    public static final s a;
    public static final s b;
    public static final /* synthetic */ s[] c;

    static {
        s sVar = new s("Default", 0);
        a = sVar;
        s sVar2 = new s("Underage", 1);
        b = sVar2;
        s[] sVarArr = {sVar, sVar2};
        c = sVarArr;
        AbstractC3328d.f(sVarArr);
    }

    public static s valueOf(String str) {
        return (s) Enum.valueOf(s.class, str);
    }

    public static s[] values() {
        return (s[]) c.clone();
    }
}
