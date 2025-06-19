package androidx.room;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class r {
    public static final r a;
    public static final r b;
    public static final r c;
    public static final /* synthetic */ r[] d;

    static {
        r rVar = new r("AUTOMATIC", 0);
        a = rVar;
        r rVar2 = new r("TRUNCATE", 1);
        b = rVar2;
        r rVar3 = new r("WRITE_AHEAD_LOGGING", 2);
        c = rVar3;
        d = new r[]{rVar, rVar2, rVar3};
    }

    public static r valueOf(String str) {
        return (r) Enum.valueOf(r.class, str);
    }

    public static r[] values() {
        return (r[]) d.clone();
    }
}
