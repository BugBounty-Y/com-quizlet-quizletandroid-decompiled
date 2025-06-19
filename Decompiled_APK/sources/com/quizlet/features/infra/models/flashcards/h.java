package com.quizlet.features.infra.models.flashcards;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class h {
    public static final h a;
    public static final h b;
    public static final /* synthetic */ h[] c;

    static {
        h hVar = new h("FRONT", 0);
        a = hVar;
        h hVar2 = new h("BACK", 1);
        b = hVar2;
        h[] hVarArr = {hVar, hVar2};
        c = hVarArr;
        AbstractC3328d.f(hVarArr);
    }

    public static h valueOf(String str) {
        return (h) Enum.valueOf(h.class, str);
    }

    public static h[] values() {
        return (h[]) c.clone();
    }
}
