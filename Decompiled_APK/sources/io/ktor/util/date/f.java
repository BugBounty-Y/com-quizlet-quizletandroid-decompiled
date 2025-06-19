package io.ktor.util.date;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class f {
    public static final com.quizlet.quizletandroid.ui.profile.b a;
    public static final /* synthetic */ f[] b;
    public static final /* synthetic */ kotlin.enums.b c;

    static {
        f[] fVarArr = {new f("MONDAY", 0), new f("TUESDAY", 1), new f("WEDNESDAY", 2), new f("THURSDAY", 3), new f("FRIDAY", 4), new f("SATURDAY", 5), new f("SUNDAY", 6)};
        b = fVarArr;
        c = AbstractC3328d.f(fVarArr);
        a = new com.quizlet.quizletandroid.ui.profile.b();
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) b.clone();
    }
}
