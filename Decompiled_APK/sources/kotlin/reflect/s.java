package kotlin.reflect;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class s {
    public static final s a;
    public static final /* synthetic */ s[] b;

    static {
        s sVar = new s("INVARIANT", 0);
        a = sVar;
        s[] sVarArr = {sVar, new s("IN", 1), new s("OUT", 2)};
        b = sVarArr;
        AbstractC3328d.f(sVarArr);
    }

    public static s valueOf(String str) {
        return (s) Enum.valueOf(s.class, str);
    }

    public static s[] values() {
        return (s[]) b.clone();
    }
}
