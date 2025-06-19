package com.quizlet.shared.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = g.class)
/* loaded from: classes3.dex */
public final class h implements serialization.b {

    @NotNull
    public static final MeteredEventType$Companion Companion;
    public static final h b;
    public static final h c;
    public static final h d;
    public static final /* synthetic */ h[] e;
    public final int a;

    static {
        h hVar = new h("EXPLANATION_VIEW", 0, 0);
        b = hVar;
        h hVar2 = new h("LEARN_CHECKPOINT", 1, 1);
        c = hVar2;
        h hVar3 = new h("TEST_SUBMISSION", 2, 2);
        d = hVar3;
        h[] hVarArr = {hVar, hVar2, hVar3};
        e = hVarArr;
        AbstractC3328d.f(hVarArr);
        Companion = new MeteredEventType$Companion();
    }

    public h(String str, int i, int i2) {
        this.a = i2;
    }

    public static h valueOf(String str) {
        return (h) Enum.valueOf(h.class, str);
    }

    public static h[] values() {
        return (h[]) e.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
