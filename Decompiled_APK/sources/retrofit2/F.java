package retrofit2;

/* loaded from: classes3.dex */
public abstract class F {
    public static final androidx.core.os.d a;
    public static final C5176a b;
    public static final C5176a c;

    static {
        String property = System.getProperty("java.vm.name");
        property.getClass();
        if (property.equals("RoboVM")) {
            a = null;
            b = new C5176a(7);
            c = new C5176a(6);
        } else if (property.equals("Dalvik")) {
            a = new androidx.core.os.d();
            b = new G(0);
            c = new C5178c(6);
        } else {
            a = null;
            b = new G(1);
            c = new C5178c(6);
        }
    }
}
