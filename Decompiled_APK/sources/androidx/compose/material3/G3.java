package androidx.compose.material3;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class G3 {
    public static final G3 a;
    public static final G3 b;
    public static final G3 c;
    public static final /* synthetic */ G3[] d;

    static {
        G3 g3 = new G3("Hidden", 0);
        a = g3;
        G3 g32 = new G3("Expanded", 1);
        b = g32;
        G3 g33 = new G3("PartiallyExpanded", 2);
        c = g33;
        d = new G3[]{g3, g32, g33};
    }

    public static G3 valueOf(String str) {
        return (G3) Enum.valueOf(G3.class, str);
    }

    public static G3[] values() {
        return (G3[]) d.clone();
    }
}
