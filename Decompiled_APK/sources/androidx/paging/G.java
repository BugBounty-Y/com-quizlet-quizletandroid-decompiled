package androidx.paging;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class G {
    public static final G a;
    public static final G b;
    public static final G c;
    public static final /* synthetic */ G[] d;

    static {
        G g = new G("REFRESH", 0);
        a = g;
        G g2 = new G("PREPEND", 1);
        b = g2;
        G g3 = new G("APPEND", 2);
        c = g3;
        d = new G[]{g, g2, g3};
    }

    public static G valueOf(String str) {
        return (G) Enum.valueOf(G.class, str);
    }

    public static G[] values() {
        return (G[]) d.clone();
    }
}
