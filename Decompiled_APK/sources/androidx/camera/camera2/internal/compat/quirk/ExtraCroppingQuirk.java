package androidx.camera.camera2.internal.compat.quirk;

import android.os.Build;
import android.util.Range;
import android.util.Size;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.core.impl.e0;
import java.util.HashMap;
import java.util.Locale;

/* loaded from: classes.dex */
public class ExtraCroppingQuirk implements e0 {
    public static final HashMap a;

    static {
        HashMap map = new HashMap();
        a = map;
        map.put("SM-T580", null);
        map.put("SM-J710MN", new Range(21, 26));
        map.put("SM-A320FL", null);
        map.put("SM-G570M", null);
        map.put("SM-G610F", null);
        map.put("SM-G610M", new Range(21, 26));
    }

    public static Size b(int i) {
        if (!c()) {
            return null;
        }
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return new Size(1920, 1080);
        }
        if (iK == 1) {
            return new Size(1280, 720);
        }
        if (iK != 2) {
            return null;
        }
        return new Size(3264, 1836);
    }

    public static boolean c() {
        if (!"samsung".equalsIgnoreCase(Build.BRAND)) {
            return false;
        }
        HashMap map = a;
        String str = Build.MODEL;
        Locale locale = Locale.US;
        if (!map.containsKey(str.toUpperCase(locale))) {
            return false;
        }
        Range range = (Range) map.get(str.toUpperCase(locale));
        if (range == null) {
            return true;
        }
        return range.contains((Range) Integer.valueOf(Build.VERSION.SDK_INT));
    }
}
