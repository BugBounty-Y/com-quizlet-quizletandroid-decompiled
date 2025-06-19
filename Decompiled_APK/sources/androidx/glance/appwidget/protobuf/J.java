package androidx.glance.appwidget.protobuf;

/* loaded from: classes.dex */
public abstract class J {
    public static final I a;
    public static final I b;

    static {
        L l = L.c;
        I i = null;
        try {
            i = (I) Class.forName("androidx.glance.appwidget.protobuf.NewInstanceSchemaFull").getDeclaredConstructor(null).newInstance(null);
        } catch (Exception unused) {
        }
        a = i;
        b = new I();
    }
}
