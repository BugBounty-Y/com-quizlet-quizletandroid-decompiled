package androidx.camera.core.impl;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class G {
    public static final G a;
    public static final G b;
    public static final G c;
    public static final /* synthetic */ G[] d;

    static {
        G g = new G("ALWAYS_OVERRIDE", 0);
        a = g;
        G g2 = new G("HIGH_PRIORITY_REQUIRED", 1);
        G g3 = new G("REQUIRED", 2);
        b = g3;
        G g4 = new G("OPTIONAL", 3);
        c = g4;
        d = new G[]{g, g2, g3, g4};
    }

    public static G valueOf(String str) {
        return (G) Enum.valueOf(G.class, str);
    }

    public static G[] values() {
        return (G[]) d.clone();
    }
}
