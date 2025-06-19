package androidx.glance.appwidget.protobuf;

/* loaded from: classes.dex */
public abstract class D {
    public static final C a;
    public static final C b;

    static {
        L l = L.c;
        C c = null;
        try {
            c = (C) Class.forName("androidx.glance.appwidget.protobuf.MapFieldSchemaFull").getDeclaredConstructor(null).newInstance(null);
        } catch (Exception unused) {
        }
        a = c;
        b = new C();
    }
}
