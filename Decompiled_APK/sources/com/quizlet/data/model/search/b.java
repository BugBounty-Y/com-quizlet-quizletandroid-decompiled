package com.quizlet.data.model.search;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class b {
    public static final com.google.mlkit.common.internal.model.a b;
    public static final b c;
    public static final /* synthetic */ b[] d;
    public static final /* synthetic */ kotlin.enums.b e;
    public final String a;

    static {
        b bVar = new b("Correct", 0, "CORRECT");
        b bVar2 = new b("Suggest", 1, "SUGGEST");
        b bVar3 = new b("None", 2, "");
        c = bVar3;
        b[] bVarArr = {bVar, bVar2, bVar3};
        d = bVarArr;
        e = AbstractC3328d.f(bVarArr);
        b = new com.google.mlkit.common.internal.model.a(24);
    }

    public b(String str, int i, String str2) {
        this.a = str2;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) d.clone();
    }
}
