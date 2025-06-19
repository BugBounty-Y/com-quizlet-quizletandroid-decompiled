package io.ktor.util.date;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class e {
    public static final com.quizlet.quizletandroid.ui.onboarding.a a;
    public static final /* synthetic */ e[] b;
    public static final /* synthetic */ kotlin.enums.b c;

    static {
        e[] eVarArr = {new e("JANUARY", 0), new e("FEBRUARY", 1), new e("MARCH", 2), new e("APRIL", 3), new e("MAY", 4), new e("JUNE", 5), new e("JULY", 6), new e("AUGUST", 7), new e("SEPTEMBER", 8), new e("OCTOBER", 9), new e("NOVEMBER", 10), new e("DECEMBER", 11)};
        b = eVarArr;
        c = AbstractC3328d.f(eVarArr);
        a = new com.quizlet.quizletandroid.ui.onboarding.a(5);
    }

    public static e valueOf(String str) {
        return (e) Enum.valueOf(e.class, str);
    }

    public static e[] values() {
        return (e[]) b.clone();
    }
}
