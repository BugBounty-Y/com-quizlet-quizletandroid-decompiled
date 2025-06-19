package com.quizlet.featuregate.contracts.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class b {
    public static final b a;
    public static final /* synthetic */ b[] b;
    public static final /* synthetic */ kotlin.enums.b c;

    static {
        b bVar = new b("CONTROL", 0);
        a = bVar;
        b[] bVarArr = {bVar, new b("GOAL_AND_KNOWLEDGE", 1), new b("GOAL_ONLY", 2), new b("KNOWLEDGE_ONLY", 3)};
        b = bVarArr;
        c = AbstractC3328d.f(bVarArr);
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) b.clone();
    }
}
