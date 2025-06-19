package androidx.constraintlayout.motion.widget;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class q {
    public static final q a;
    public static final q b;
    public static final q c;
    public static final q d;
    public static final /* synthetic */ q[] e;

    static {
        q qVar = new q("UNDEFINED", 0);
        a = qVar;
        q qVar2 = new q("SETUP", 1);
        b = qVar2;
        q qVar3 = new q("MOVING", 2);
        c = qVar3;
        q qVar4 = new q("FINISHED", 3);
        d = qVar4;
        e = new q[]{qVar, qVar2, qVar3, qVar4};
    }

    public static q valueOf(String str) {
        return (q) Enum.valueOf(q.class, str);
    }

    public static q[] values() {
        return (q[]) e.clone();
    }
}
