package coil3.decode;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class h {
    public static final h a;
    public static final h b;
    public static final h c;
    public static final h d;
    public static final /* synthetic */ h[] e;

    static {
        h hVar = new h("MEMORY_CACHE", 0);
        a = hVar;
        h hVar2 = new h("MEMORY", 1);
        b = hVar2;
        h hVar3 = new h("DISK", 2);
        c = hVar3;
        h hVar4 = new h("NETWORK", 3);
        d = hVar4;
        h[] hVarArr = {hVar, hVar2, hVar3, hVar4};
        e = hVarArr;
        AbstractC3328d.f(hVarArr);
    }

    public static h valueOf(String str) {
        return (h) Enum.valueOf(h.class, str);
    }

    public static h[] values() {
        return (h[]) e.clone();
    }
}
