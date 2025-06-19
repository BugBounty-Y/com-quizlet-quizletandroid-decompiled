package androidx.fragment.app.strictmode;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class a {
    public static final a a;
    public static final a b;
    public static final a c;
    public static final a d;
    public static final a e;
    public static final a f;
    public static final a g;
    public static final /* synthetic */ a[] h;

    /* JADX INFO: Fake field, exist only in values array */
    a EF0;

    static {
        a aVar = new a("PENALTY_LOG", 0);
        a aVar2 = new a("PENALTY_DEATH", 1);
        a aVar3 = new a("DETECT_FRAGMENT_REUSE", 2);
        a = aVar3;
        a aVar4 = new a("DETECT_FRAGMENT_TAG_USAGE", 3);
        b = aVar4;
        a aVar5 = new a("DETECT_WRONG_NESTED_HIERARCHY", 4);
        c = aVar5;
        a aVar6 = new a("DETECT_RETAIN_INSTANCE_USAGE", 5);
        d = aVar6;
        a aVar7 = new a("DETECT_SET_USER_VISIBLE_HINT", 6);
        e = aVar7;
        a aVar8 = new a("DETECT_TARGET_FRAGMENT_USAGE", 7);
        f = aVar8;
        a aVar9 = new a("DETECT_WRONG_FRAGMENT_CONTAINER", 8);
        g = aVar9;
        h = new a[]{aVar, aVar2, aVar3, aVar4, aVar5, aVar6, aVar7, aVar8, aVar9};
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) h.clone();
    }
}
