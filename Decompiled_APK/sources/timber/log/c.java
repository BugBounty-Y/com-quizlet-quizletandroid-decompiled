package timber.log;

import java.util.ArrayList;

/* loaded from: classes3.dex */
public abstract class c {
    public static final a a = new a();
    public static final ArrayList b = new ArrayList();
    public static volatile b[] c = new b[0];

    public static void a(Throwable th) {
        a.e(th);
    }

    public static void b(Throwable th) {
        a.p(th);
    }
}
