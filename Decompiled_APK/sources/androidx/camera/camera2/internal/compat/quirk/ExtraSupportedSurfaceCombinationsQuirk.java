package androidx.camera.camera2.internal.compat.quirk;

import android.os.Build;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.core.impl.C0169h;
import androidx.camera.core.impl.e0;
import androidx.camera.core.impl.t0;
import androidx.camera.core.impl.u0;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;

/* loaded from: classes.dex */
public class ExtraSupportedSurfaceCombinationsQuirk implements e0 {
    public static final t0 a;
    public static final t0 b;
    public static final HashSet c;
    public static final HashSet d;

    static {
        t0 t0Var = new t0();
        u0 u0Var = u0.VGA;
        AbstractC0147y.i(2, u0Var, 0L, t0Var);
        u0 u0Var2 = u0.PREVIEW;
        AbstractC0147y.i(1, u0Var2, 0L, t0Var);
        u0 u0Var3 = u0.MAXIMUM;
        AbstractC0147y.i(2, u0Var3, 0L, t0Var);
        a = t0Var;
        t0 t0Var2 = new t0();
        t0Var2.a(new C0169h(1, u0Var2, 0L));
        t0Var2.a(new C0169h(1, u0Var, 0L));
        AbstractC0147y.i(2, u0Var3, 0L, t0Var2);
        b = t0Var2;
        c = new HashSet(Arrays.asList("PIXEL 6", "PIXEL 6 PRO", "PIXEL 7", "PIXEL 7 PRO", "PIXEL 8", "PIXEL 8 PRO"));
        d = new HashSet(Arrays.asList("SM-S921", "SC-51E", "SCG25", "SM-S926", "SM-S928", "SC-52E", "SCG26"));
    }

    public static boolean b() {
        if (!"samsung".equalsIgnoreCase(Build.BRAND)) {
            return false;
        }
        String upperCase = Build.MODEL.toUpperCase(Locale.US);
        Iterator it2 = d.iterator();
        while (it2.hasNext()) {
            if (upperCase.startsWith((String) it2.next())) {
                return true;
            }
        }
        return false;
    }
}
