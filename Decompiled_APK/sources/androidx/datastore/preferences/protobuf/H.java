package androidx.datastore.preferences.protobuf;

/* loaded from: classes.dex */
public abstract class H {
    public static final G a;
    public static final G b;

    static {
        Q q = Q.c;
        G g = null;
        try {
            g = (G) Class.forName("androidx.datastore.preferences.protobuf.MapFieldSchemaFull").getDeclaredConstructor(null).newInstance(null);
        } catch (Exception unused) {
        }
        a = g;
        b = new G();
    }
}
