package androidx.datastore.preferences.protobuf;

/* renamed from: androidx.datastore.preferences.protobuf.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1108o {
    public static final C1107n a = new C1107n();
    public static final C1107n b;

    static {
        Q q = Q.c;
        C1107n c1107n = null;
        try {
            c1107n = (C1107n) Class.forName("androidx.datastore.preferences.protobuf.ExtensionSchemaFull").getDeclaredConstructor(null).newInstance(null);
        } catch (Exception unused) {
        }
        b = c1107n;
    }
}
