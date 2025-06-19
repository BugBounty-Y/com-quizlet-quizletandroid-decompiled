package com.ionspin.kotlin.bignum.decimal;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class c {
    public static final c a;
    public static final c b;
    public static final c c;
    public static final /* synthetic */ c[] d;

    static {
        c cVar = new c("FLOOR", 0);
        a = cVar;
        c cVar2 = new c("CEILING", 1);
        c cVar3 = new c("AWAY_FROM_ZERO", 2);
        c cVar4 = new c("TOWARDS_ZERO", 3);
        c cVar5 = new c("NONE", 4);
        b = cVar5;
        c cVar6 = new c("ROUND_HALF_AWAY_FROM_ZERO", 5);
        c = cVar6;
        d = new c[]{cVar, cVar2, cVar3, cVar4, cVar5, cVar6, new c("ROUND_HALF_TOWARDS_ZERO", 6), new c("ROUND_HALF_CEILING", 7), new c("ROUND_HALF_FLOOR", 8), new c("ROUND_HALF_TO_EVEN", 9), new c("ROUND_HALF_TO_ODD", 10)};
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) d.clone();
    }
}
