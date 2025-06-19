package androidx.compose.material3.tokens;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class G {
    public static final G a;
    public static final G b;
    public static final G c;
    public static final G d;
    public static final G e;
    public static final G f;
    public static final G g;
    public static final G h;
    public static final G i;
    public static final G j;
    public static final /* synthetic */ G[] k;

    static {
        G g2 = new G("BodyLarge", 0);
        a = g2;
        G g3 = new G("BodyMedium", 1);
        b = g3;
        G g4 = new G("BodySmall", 2);
        G g5 = new G("DisplayLarge", 3);
        G g6 = new G("DisplayMedium", 4);
        G g7 = new G("DisplaySmall", 5);
        G g8 = new G("HeadlineLarge", 6);
        c = g8;
        G g9 = new G("HeadlineMedium", 7);
        d = g9;
        G g10 = new G("HeadlineSmall", 8);
        e = g10;
        G g11 = new G("LabelLarge", 9);
        f = g11;
        G g12 = new G("LabelMedium", 10);
        g = g12;
        G g13 = new G("LabelSmall", 11);
        h = g13;
        G g14 = new G("TitleLarge", 12);
        i = g14;
        G g15 = new G("TitleMedium", 13);
        G g16 = new G("TitleSmall", 14);
        j = g16;
        k = new G[]{g2, g3, g4, g5, g6, g7, g8, g9, g10, g11, g12, g13, g14, g15, g16};
    }

    public static G valueOf(String str) {
        return (G) Enum.valueOf(G.class, str);
    }

    public static G[] values() {
        return (G[]) k.clone();
    }
}
