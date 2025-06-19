package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class G1 {
    public static final G1 a;
    public static final G1 b;
    public static final G1 c;
    public static final G1 d;
    public static final /* synthetic */ G1[] e;

    static {
        G1 g1 = new G1("Success", 0);
        a = g1;
        G1 g12 = new G1("EmailNotFound", 1);
        b = g12;
        G1 g13 = new G1("AlreadySent", 2);
        c = g13;
        G1 g14 = new G1("ExceededLimit", 3);
        G1 g15 = new G1("Unknown", 4);
        d = g15;
        G1[] g1Arr = {g1, g12, g13, g14, g15};
        e = g1Arr;
        AbstractC3328d.f(g1Arr);
    }

    public static G1 valueOf(String str) {
        return (G1) Enum.valueOf(G1.class, str);
    }

    public static G1[] values() {
        return (G1[]) e.clone();
    }
}
