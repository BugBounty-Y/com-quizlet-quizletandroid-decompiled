package com.google.protobuf;

/* loaded from: classes2.dex */
public abstract class W {
    public static final V a;
    public static final V b;

    static {
        V v = null;
        try {
            v = (V) Class.forName("com.google.protobuf.NewInstanceSchemaFull").getDeclaredConstructor(null).newInstance(null);
        } catch (Exception unused) {
        }
        a = v;
        b = new V();
    }
}
