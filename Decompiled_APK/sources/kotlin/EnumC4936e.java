package kotlin;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: kotlin.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class EnumC4936e {
    public static final EnumC4936e a;
    public static final /* synthetic */ EnumC4936e[] b;

    static {
        EnumC4936e enumC4936e = new EnumC4936e("WARNING", 0);
        a = enumC4936e;
        EnumC4936e[] enumC4936eArr = {enumC4936e, new EnumC4936e("ERROR", 1), new EnumC4936e("HIDDEN", 2)};
        b = enumC4936eArr;
        AbstractC3328d.f(enumC4936eArr);
    }

    public static EnumC4936e valueOf(String str) {
        return (EnumC4936e) Enum.valueOf(EnumC4936e.class, str);
    }

    public static EnumC4936e[] values() {
        return (EnumC4936e[]) b.clone();
    }
}
