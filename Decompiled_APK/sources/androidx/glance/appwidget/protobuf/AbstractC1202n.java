package androidx.glance.appwidget.protobuf;

/* renamed from: androidx.glance.appwidget.protobuf.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1202n {
    public static final C1201m a = new C1201m();
    public static final C1201m b;

    static {
        L l = L.c;
        C1201m c1201m = null;
        try {
            c1201m = (C1201m) Class.forName("androidx.glance.appwidget.protobuf.ExtensionSchemaFull").getDeclaredConstructor(null).newInstance(null);
        } catch (Exception unused) {
        }
        b = c1201m;
    }
}
