package com.google.protobuf;

/* renamed from: com.google.protobuf.p, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC4022p {
    public static final C4021o a = new C4021o();
    public static final C4021o b;

    static {
        C4021o c4021o = null;
        try {
            c4021o = (C4021o) Class.forName("com.google.protobuf.ExtensionSchemaFull").getDeclaredConstructor(null).newInstance(null);
        } catch (Exception unused) {
        }
        b = c4021o;
    }
}
