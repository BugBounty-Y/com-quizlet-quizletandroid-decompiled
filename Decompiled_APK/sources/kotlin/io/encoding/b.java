package kotlin.io.encoding;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class b {
    public static final /* synthetic */ b[] a;

    static {
        b[] bVarArr = {new b("PRESENT", 0), new b("ABSENT", 1), new b("PRESENT_OPTIONAL", 2), new b("ABSENT_OPTIONAL", 3)};
        a = bVarArr;
        AbstractC3328d.f(bVarArr);
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) a.clone();
    }
}
