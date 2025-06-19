package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class D3 implements C3 {
    public static final F1 a;
    public static final F1 b;
    public static final F1 c;
    public static final F1 d;
    public static final F1 e;
    public static final F1 f;

    static {
        androidx.appcompat.app.K k = new androidx.appcompat.app.K(B1.a(), true, true);
        a = k.Q("measurement.test.boolean_flag", false);
        b = k.O(-1L, "measurement.test.cached_long_flag");
        Double dValueOf = Double.valueOf(-3.0d);
        Object obj = F1.g;
        c = new F1(k, "measurement.test.double_flag", dValueOf, 2);
        d = k.O(-2L, "measurement.test.int_flag");
        e = k.O(-1L, "measurement.test.long_flag");
        f = k.P("measurement.test.string_flag", "---");
    }
}
