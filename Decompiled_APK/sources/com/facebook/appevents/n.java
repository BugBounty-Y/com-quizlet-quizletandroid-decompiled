package com.facebook.appevents;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class n {
    public static final n a;
    public static final n b;
    public static final n c;
    public static final n d;
    public static final /* synthetic */ n[] e;

    static {
        n nVar = new n("EXPLICIT", 0);
        a = nVar;
        n nVar2 = new n("TIMER", 1);
        b = nVar2;
        n nVar3 = new n("SESSION_CHANGE", 2);
        n nVar4 = new n("PERSISTED_EVENTS", 3);
        n nVar5 = new n("EVENT_THRESHOLD", 4);
        c = nVar5;
        n nVar6 = new n("EAGER_FLUSHING_EVENT", 5);
        d = nVar6;
        e = new n[]{nVar, nVar2, nVar3, nVar4, nVar5, nVar6};
    }

    public static n valueOf(String str) {
        return (n) Enum.valueOf(n.class, str);
    }

    public static n[] values() {
        return (n[]) e.clone();
    }
}
