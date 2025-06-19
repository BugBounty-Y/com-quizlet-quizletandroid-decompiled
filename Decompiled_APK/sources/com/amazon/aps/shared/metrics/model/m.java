package com.amazon.aps.shared.metrics.model;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class m {
    public static final m a;
    public static final m b;
    public static final /* synthetic */ m[] c;

    static {
        m mVar = new m("Success", 0);
        a = mVar;
        m mVar2 = new m("Failure", 1);
        b = mVar2;
        c = new m[]{mVar, mVar2};
    }

    public static m valueOf(String str) {
        return (m) Enum.valueOf(m.class, str);
    }

    public static m[] values() {
        return (m[]) c.clone();
    }
}
