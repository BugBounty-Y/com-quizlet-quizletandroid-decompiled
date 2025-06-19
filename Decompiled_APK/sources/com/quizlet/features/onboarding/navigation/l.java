package com.quizlet.features.onboarding.navigation;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class l {
    public static final com.google.android.material.shape.e a;
    public static final l b;
    public static final l c;
    public static final l d;
    public static final l e;
    public static final /* synthetic */ l[] f;

    static {
        l lVar = new l("SURVEY", 0);
        b = lVar;
        l lVar2 = new l("FLASHCARDS", 1);
        c = lVar2;
        l lVar3 = new l("Q_PLUS_UPSELL", 2);
        d = lVar3;
        l lVar4 = new l("FINISH", 3);
        e = lVar4;
        l[] lVarArr = {lVar, lVar2, lVar3, lVar4};
        f = lVarArr;
        AbstractC3328d.f(lVarArr);
        a = new com.google.android.material.shape.e(27);
    }

    public static l valueOf(String str) {
        return (l) Enum.valueOf(l.class, str);
    }

    public static l[] values() {
        return (l[]) f.clone();
    }
}
