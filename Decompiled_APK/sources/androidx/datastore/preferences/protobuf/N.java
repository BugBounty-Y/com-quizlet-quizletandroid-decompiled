package androidx.datastore.preferences.protobuf;

/* loaded from: classes.dex */
public abstract class N {
    public static final M a;
    public static final M b;

    static {
        Q q = Q.c;
        M m = null;
        try {
            m = (M) Class.forName("androidx.datastore.preferences.protobuf.NewInstanceSchemaFull").getDeclaredConstructor(null).newInstance(null);
        } catch (Exception unused) {
        }
        a = m;
        b = new M();
    }
}
