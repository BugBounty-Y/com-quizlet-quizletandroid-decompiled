package androidx.navigation;

import android.os.Bundle;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class S {
    public static final C1284f b;
    public static final C1283e c;
    public static final C1283e d;
    public static final C1284f e;
    public static final C1283e f;
    public static final C1283e g;
    public static final C1284f h;
    public static final C1283e i;
    public static final C1283e j;
    public static final C1284f k;
    public static final C1283e l;
    public static final C1283e m;
    public static final C1284f n;
    public static final C1283e o;
    public static final C1283e p;
    public final boolean a;

    static {
        boolean z = false;
        b = new C1284f(z, 2);
        boolean z2 = true;
        c = new C1283e(z2, 4);
        d = new C1283e(z2, 5);
        e = new C1284f(z, 3);
        f = new C1283e(z2, 6);
        g = new C1283e(z2, 7);
        h = new C1284f(z, 1);
        i = new C1283e(z2, 2);
        j = new C1283e(z2, 3);
        k = new C1284f(z, 0);
        l = new C1283e(z2, 0);
        m = new C1283e(z2, 1);
        n = new C1284f(z2, 4);
        o = new C1283e(z2, 8);
        p = new C1283e(z2, 9);
    }

    public S(boolean z) {
        this.a = z;
    }

    public abstract Object a(Bundle bundle, String str);

    public abstract String b();

    public Object c(Object obj, String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        return d(value);
    }

    public abstract Object d(String str);

    public abstract void e(Bundle bundle, String str, Object obj);

    public String f(Object obj) {
        return String.valueOf(obj);
    }

    public boolean g(Object obj, Object obj2) {
        return Intrinsics.b(obj, obj2);
    }

    public final String toString() {
        return b();
    }
}
