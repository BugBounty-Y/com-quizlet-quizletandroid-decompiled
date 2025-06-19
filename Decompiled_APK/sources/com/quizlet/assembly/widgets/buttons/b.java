package com.quizlet.assembly.widgets.buttons;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class b {
    public static final com.quizlet.shared.usecase.srs.a b;
    public static final b c;
    public static final /* synthetic */ b[] d;
    public final int a;

    static {
        b bVar = new b("LINK", 0, 1);
        b bVar2 = new b("SUBTLE", 1, 2);
        c = bVar2;
        b[] bVarArr = {bVar, bVar2, new b("ALWAYS_DARK", 2, 3)};
        d = bVarArr;
        AbstractC3328d.f(bVarArr);
        b = new com.quizlet.shared.usecase.srs.a(23);
    }

    public b(String str, int i, int i2) {
        this.a = i2;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) d.clone();
    }
}
