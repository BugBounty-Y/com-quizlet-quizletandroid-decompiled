package androidx.camera.camera2.internal;

import android.os.Build;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0;
import androidx.camera.core.impl.C0162c;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/* loaded from: classes.dex */
public abstract class e0 {
    public static final C0162c a = new C0162c("camera2.streamSpec.streamUseCase", Long.TYPE, null);
    public static final HashMap b;
    public static final HashMap c;

    static {
        HashMap map = new HashMap();
        b = map;
        HashMap map2 = new HashMap();
        c = map2;
        if (Build.VERSION.SDK_INT >= 33) {
            HashSet hashSet = new HashSet();
            C0 c0 = C0.b;
            hashSet.add(c0);
            C0 c02 = C0.f;
            hashSet.add(c02);
            map.put(4L, hashSet);
            HashSet hashSet2 = new HashSet();
            hashSet2.add(c0);
            hashSet2.add(c02);
            hashSet2.add(C0.c);
            map.put(1L, hashSet2);
            HashSet hashSet3 = new HashSet();
            C0 c03 = C0.a;
            hashSet3.add(c03);
            map.put(2L, hashSet3);
            HashSet hashSet4 = new HashSet();
            C0 c04 = C0.d;
            hashSet4.add(c04);
            map.put(3L, hashSet4);
            HashSet hashSet5 = new HashSet();
            hashSet5.add(c0);
            hashSet5.add(c03);
            hashSet5.add(c04);
            map2.put(4L, hashSet5);
            HashSet hashSet6 = new HashSet();
            hashSet6.add(c0);
            hashSet6.add(c04);
            map2.put(3L, hashSet6);
        }
    }

    public static androidx.camera.camera2.impl.b a(androidx.camera.camera2.impl.b bVar, long j) {
        C0162c c0162c = a;
        if (bVar.c(c0162c) && ((Long) bVar.e(c0162c)).longValue() == j) {
            return null;
        }
        androidx.camera.core.impl.X xK = androidx.camera.core.impl.X.k(bVar);
        xK.m(c0162c, Long.valueOf(j));
        return new androidx.camera.camera2.impl.b(xK, 4);
    }

    public static boolean b(C0 c0, long j, List list) {
        if (Build.VERSION.SDK_INT < 33) {
            return false;
        }
        if (c0 != C0.e) {
            HashMap map = b;
            return map.containsKey(Long.valueOf(j)) && ((Set) map.get(Long.valueOf(j))).contains(c0);
        }
        HashMap map2 = c;
        if (!map2.containsKey(Long.valueOf(j))) {
            return false;
        }
        Set set = (Set) map2.get(Long.valueOf(j));
        if (list.size() != set.size()) {
            return false;
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            if (!set.contains((C0) it2.next())) {
                return false;
            }
        }
        return true;
    }

    public static boolean c(androidx.camera.core.impl.j0 j0Var, C0 c0) {
        if (((Boolean) j0Var.j(A0.t0, Boolean.FALSE)).booleanValue()) {
            return false;
        }
        C0162c c0162c = androidx.camera.core.impl.N.b;
        if (j0Var.c(c0162c)) {
            return c0.ordinal() == 0 && ((Integer) j0Var.e(c0162c)).intValue() == 2;
        }
        return false;
    }
}
