package kotlinx.coroutines;

/* loaded from: classes3.dex */
public abstract class C0 {
    public static final ThreadLocal a = new ThreadLocal();

    public static Z a() {
        ThreadLocal threadLocal = a;
        Z z = (Z) threadLocal.get();
        if (z != null) {
            return z;
        }
        C5020h c5020h = new C5020h(Thread.currentThread());
        threadLocal.set(c5020h);
        return c5020h;
    }
}
