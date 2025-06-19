package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.quizlet.data.model.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC4110b {
    public static final /* synthetic */ EnumC4110b[] a;

    static {
        EnumC4110b[] enumC4110bArr = {new EnumC4110b("TOP", 0), new EnumC4110b("MIDDLE", 1), new EnumC4110b("BOTTOM", 2)};
        a = enumC4110bArr;
        AbstractC3328d.f(enumC4110bArr);
    }

    public static EnumC4110b valueOf(String str) {
        return (EnumC4110b) Enum.valueOf(EnumC4110b.class, str);
    }

    public static EnumC4110b[] values() {
        return (EnumC4110b[]) a.clone();
    }
}
