package com.quizlet.features.infra.models.flashcards;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class c {
    public static final com.quizlet.shared.usecase.studiableMetadata.a b;
    public static final c c;
    public static final c d;
    public static final /* synthetic */ c[] e;
    public final int a;

    static {
        c cVar = new c("QUIZ_MODE", 0, 0);
        c = cVar;
        c cVar2 = new c("REVIEW_MODE", 1, 1);
        d = cVar2;
        c[] cVarArr = {cVar, cVar2};
        e = cVarArr;
        AbstractC3328d.f(cVarArr);
        b = new com.quizlet.shared.usecase.studiableMetadata.a(26);
    }

    public c(String str, int i, int i2) {
        this.a = i2;
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) e.clone();
    }
}
