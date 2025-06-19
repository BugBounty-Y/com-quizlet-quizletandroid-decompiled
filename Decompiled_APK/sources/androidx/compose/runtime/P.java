package androidx.compose.runtime;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class P {
    public static final P a;
    public static final P b;
    public static final P c;
    public static final P d;
    public static final /* synthetic */ P[] e;

    static {
        P p = new P("IGNORED", 0);
        a = p;
        P p2 = new P("SCHEDULED", 1);
        b = p2;
        P p3 = new P("DEFERRED", 2);
        c = p3;
        P p4 = new P("IMMINENT", 3);
        d = p4;
        P[] pArr = {p, p2, p3, p4};
        e = pArr;
        AbstractC3328d.f(pArr);
    }

    public static P valueOf(String str) {
        return (P) Enum.valueOf(P.class, str);
    }

    public static P[] values() {
        return (P[]) e.clone();
    }
}
