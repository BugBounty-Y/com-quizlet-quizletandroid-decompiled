package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.data.model.t0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC4167t0 {
    public static final EnumC4167t0 a;
    public static final EnumC4167t0 b;
    public static final EnumC4167t0 c;
    public static final /* synthetic */ EnumC4167t0[] d;

    static {
        EnumC4167t0 enumC4167t0 = new EnumC4167t0("None", 0);
        a = enumC4167t0;
        EnumC4167t0 enumC4167t02 = new EnumC4167t0("SubscriptionPending", 1);
        b = enumC4167t02;
        EnumC4167t0 enumC4167t03 = new EnumC4167t0("UnsavedDrafts", 2);
        c = enumC4167t03;
        EnumC4167t0[] enumC4167t0Arr = {enumC4167t0, enumC4167t02, enumC4167t03};
        d = enumC4167t0Arr;
        AbstractC3328d.f(enumC4167t0Arr);
    }

    public static EnumC4167t0 valueOf(String str) {
        return (EnumC4167t0) Enum.valueOf(EnumC4167t0.class, str);
    }

    public static EnumC4167t0[] values() {
        return (EnumC4167t0[]) d.clone();
    }
}
