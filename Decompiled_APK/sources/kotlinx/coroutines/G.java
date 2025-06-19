package kotlinx.coroutines;

/* loaded from: classes3.dex */
public abstract class G {
    public static final J a;

    static {
        String property;
        J j;
        int i = kotlinx.coroutines.internal.s.a;
        try {
            property = System.getProperty("kotlinx.coroutines.main.delay");
        } catch (SecurityException unused) {
            property = null;
        }
        if (property != null ? Boolean.parseBoolean(property) : false) {
            kotlinx.coroutines.scheduling.e eVar = O.a;
            kotlinx.coroutines.android.d dVar = kotlinx.coroutines.internal.m.a;
            kotlinx.coroutines.android.d dVar2 = dVar.e;
            j = dVar;
            if (dVar == null) {
                j = F.i;
            }
        } else {
            j = F.i;
        }
        a = j;
    }
}
