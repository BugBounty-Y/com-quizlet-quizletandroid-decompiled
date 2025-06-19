package androidx.glance.appwidget.protobuf;

/* loaded from: classes.dex */
public final class C {
    public static B a(Object obj, Object obj2) {
        B bE = (B) obj;
        B b = (B) obj2;
        if (!b.isEmpty()) {
            if (!bE.a) {
                bE = bE.e();
            }
            bE.d();
            if (!b.isEmpty()) {
                bE.putAll(b);
            }
        }
        return bE;
    }
}
