package androidx.constraintlayout.core.widgets;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class d {
    public static final d a;
    public static final d b;
    public static final d c;
    public static final d d;
    public static final /* synthetic */ d[] e;

    static {
        d dVar = new d("FIXED", 0);
        a = dVar;
        d dVar2 = new d("WRAP_CONTENT", 1);
        b = dVar2;
        d dVar3 = new d("MATCH_CONSTRAINT", 2);
        c = dVar3;
        d dVar4 = new d("MATCH_PARENT", 3);
        d = dVar4;
        e = new d[]{dVar, dVar2, dVar3, dVar4};
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) e.clone();
    }
}
