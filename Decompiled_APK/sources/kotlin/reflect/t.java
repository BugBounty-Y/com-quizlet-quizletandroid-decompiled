package kotlin.reflect;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class t {
    public static final /* synthetic */ t[] a;

    static {
        t[] tVarArr = {new t("PUBLIC", 0), new t("PROTECTED", 1), new t("INTERNAL", 2), new t("PRIVATE", 3)};
        a = tVarArr;
        AbstractC3328d.f(tVarArr);
    }

    public static t valueOf(String str) {
        return (t) Enum.valueOf(t.class, str);
    }

    public static t[] values() {
        return (t[]) a.clone();
    }
}
