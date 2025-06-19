package com.quizlet.upgrade.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class F {
    public static final F b;
    public static final F c;
    public static final /* synthetic */ F[] d;
    public final String a;

    static {
        F f = new F("ClassProgress", 0, "https://help.quizlet.com/hc/en-us/articles/360030512432");
        b = f;
        F f2 = new F("QuizletLive", 1, "https://help.quizlet.com/hc/en-us/articles/360031211971");
        c = f2;
        F[] fArr = {f, f2};
        d = fArr;
        AbstractC3328d.f(fArr);
    }

    public F(String str, int i, String str2) {
        this.a = str2;
    }

    public static F valueOf(String str) {
        return (F) Enum.valueOf(F.class, str);
    }

    public static F[] values() {
        return (F[]) d.clone();
    }
}
