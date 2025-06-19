package androidx.datastore.preferences.protobuf;

/* loaded from: classes.dex */
public abstract class A {
    public static final C1118z a;
    public static final C1118z b;

    static {
        Q q = Q.c;
        C1118z c1118z = null;
        try {
            c1118z = (C1118z) Class.forName("androidx.datastore.preferences.protobuf.ListFieldSchemaFull").getDeclaredConstructor(null).newInstance(null);
        } catch (Exception unused) {
        }
        a = c1118z;
        b = new C1118z();
    }
}
