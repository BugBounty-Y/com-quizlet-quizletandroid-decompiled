package kotlinx.coroutines;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class D {
    public static final D a;
    public static final D b;
    public static final D c;
    public static final D d;
    public static final /* synthetic */ D[] e;

    static {
        D d2 = new D("DEFAULT", 0);
        a = d2;
        D d3 = new D("LAZY", 1);
        b = d3;
        D d4 = new D("ATOMIC", 2);
        c = d4;
        D d5 = new D("UNDISPATCHED", 3);
        d = d5;
        D[] dArr = {d2, d3, d4, d5};
        e = dArr;
        AbstractC3328d.f(dArr);
    }

    public static D valueOf(String str) {
        return (D) Enum.valueOf(D.class, str);
    }

    public static D[] values() {
        return (D[]) e.clone();
    }
}
