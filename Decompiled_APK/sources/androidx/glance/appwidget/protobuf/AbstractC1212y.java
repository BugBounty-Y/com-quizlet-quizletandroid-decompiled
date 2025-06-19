package androidx.glance.appwidget.protobuf;

/* renamed from: androidx.glance.appwidget.protobuf.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1212y {
    public static final C1211x a;
    public static final C1211x b;

    static {
        L l = L.c;
        C1211x c1211x = null;
        try {
            c1211x = (C1211x) Class.forName("androidx.glance.appwidget.protobuf.ListFieldSchemaFull").getDeclaredConstructor(null).newInstance(null);
        } catch (Exception unused) {
        }
        a = c1211x;
        b = new C1211x();
    }
}
