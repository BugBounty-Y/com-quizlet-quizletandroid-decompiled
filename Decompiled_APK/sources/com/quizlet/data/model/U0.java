package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class U0 {
    public static final C4170u0 b;
    public static final U0 c;
    public static final U0 d;
    public static final U0 e;
    public static final U0 f;
    public static final /* synthetic */ U0[] g;
    public static final /* synthetic */ kotlin.enums.b h;
    public final String a;

    static {
        U0 u0 = new U0("DETAIL", 0, "detail");
        c = u0;
        U0 u02 = new U0("RESULTS", 1, "results");
        d = u02;
        U0 u03 = new U0("UPLOAD", 2, "upload");
        e = u03;
        U0 u04 = new U0("DEEPLINK", 3, "deeplink");
        f = u04;
        U0[] u0Arr = {u0, u02, u03, u04};
        g = u0Arr;
        h = AbstractC3328d.f(u0Arr);
        b = new C4170u0();
    }

    public U0(String str, int i, String str2) {
        this.a = str2;
    }

    public static U0 valueOf(String str) {
        return (U0) Enum.valueOf(U0.class, str);
    }

    public static U0[] values() {
        return (U0[]) g.clone();
    }
}
