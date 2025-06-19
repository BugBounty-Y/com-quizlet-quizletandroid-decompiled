package androidx.camera.camera2.internal.compat.params;

import android.hardware.camera2.params.DynamicRangeProfiles;
import androidx.camera.core.C0196t;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/* loaded from: classes.dex */
public abstract class a {
    public static final HashMap a;
    public static final HashMap b;

    static {
        C0196t c0196t;
        HashMap map = new HashMap();
        a = map;
        HashMap map2 = new HashMap();
        b = map2;
        C0196t c0196t2 = C0196t.d;
        map.put(1L, c0196t2);
        map2.put(c0196t2, Collections.singletonList(1L));
        map.put(2L, C0196t.e);
        map2.put((C0196t) map.get(2L), Collections.singletonList(2L));
        C0196t c0196t3 = C0196t.f;
        map.put(4L, c0196t3);
        map2.put(c0196t3, Collections.singletonList(4L));
        C0196t c0196t4 = C0196t.g;
        map.put(8L, c0196t4);
        map2.put(c0196t4, Collections.singletonList(8L));
        List listAsList = Arrays.asList(64L, 128L, 16L, 32L);
        Iterator it2 = listAsList.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            c0196t = C0196t.h;
            if (!zHasNext) {
                break;
            }
            a.put((Long) it2.next(), c0196t);
        }
        b.put(c0196t, listAsList);
        List listAsList2 = Arrays.asList(1024L, 2048L, 256L, 512L);
        Iterator it3 = listAsList2.iterator();
        while (true) {
            boolean zHasNext2 = it3.hasNext();
            C0196t c0196t5 = C0196t.i;
            if (!zHasNext2) {
                b.put(c0196t5, listAsList2);
                return;
            } else {
                a.put((Long) it3.next(), c0196t5);
            }
        }
    }

    public static Long a(C0196t c0196t, DynamicRangeProfiles dynamicRangeProfiles) {
        List<Long> list = (List) b.get(c0196t);
        if (list == null) {
            return null;
        }
        Set supportedProfiles = dynamicRangeProfiles.getSupportedProfiles();
        for (Long l : list) {
            if (supportedProfiles.contains(l)) {
                return l;
            }
        }
        return null;
    }
}
