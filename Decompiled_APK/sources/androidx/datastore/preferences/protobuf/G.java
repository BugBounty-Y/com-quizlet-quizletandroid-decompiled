package androidx.datastore.preferences.protobuf;

/* loaded from: classes.dex */
public final class G {
    public static F a(Object obj, Object obj2) {
        F fD = (F) obj;
        F f = (F) obj2;
        if (!f.isEmpty()) {
            if (!fD.a) {
                fD = fD.d();
            }
            fD.b();
            if (!f.isEmpty()) {
                fD.putAll(f);
            }
        }
        return fD;
    }
}
