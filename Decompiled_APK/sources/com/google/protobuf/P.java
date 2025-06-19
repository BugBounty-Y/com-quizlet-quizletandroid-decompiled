package com.google.protobuf;

/* loaded from: classes2.dex */
public abstract class P {
    public static final O a;
    public static final O b;

    static {
        O o = null;
        try {
            o = (O) Class.forName("com.google.protobuf.MapFieldSchemaFull").getDeclaredConstructor(null).newInstance(null);
        } catch (Exception unused) {
        }
        a = o;
        b = new O();
    }
}
