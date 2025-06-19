package androidx.sqlite.db.framework;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class e {
    public static final e a;
    public static final e b;
    public static final e c;
    public static final e d;
    public static final e e;
    public static final /* synthetic */ e[] f;

    static {
        e eVar = new e("ON_CONFIGURE", 0);
        a = eVar;
        e eVar2 = new e("ON_CREATE", 1);
        b = eVar2;
        e eVar3 = new e("ON_UPGRADE", 2);
        c = eVar3;
        e eVar4 = new e("ON_DOWNGRADE", 3);
        d = eVar4;
        e eVar5 = new e("ON_OPEN", 4);
        e = eVar5;
        f = new e[]{eVar, eVar2, eVar3, eVar4, eVar5};
    }

    public static e valueOf(String str) {
        return (e) Enum.valueOf(e.class, str);
    }

    public static e[] values() {
        return (e[]) f.clone();
    }
}
