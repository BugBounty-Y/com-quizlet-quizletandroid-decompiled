package androidx.camera.core.impl;

import android.hardware.camera2.params.InputConfiguration;
import android.util.ArrayMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public final class q0 {
    public static final List i = Arrays.asList(1, 5, 3);
    public final ArrayList a;
    public final C0166e b;
    public final List c;
    public final List d;
    public final List e;
    public final o0 f;
    public final F g;
    public final InputConfiguration h;

    public q0(ArrayList arrayList, ArrayList arrayList2, ArrayList arrayList3, ArrayList arrayList4, F f, o0 o0Var, InputConfiguration inputConfiguration, C0166e c0166e) {
        this.a = arrayList;
        this.c = Collections.unmodifiableList(arrayList2);
        this.d = Collections.unmodifiableList(arrayList3);
        this.e = Collections.unmodifiableList(arrayList4);
        this.f = o0Var;
        this.g = f;
        this.h = inputConfiguration;
        this.b = c0166e;
    }

    public static q0 a() {
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList(0);
        ArrayList arrayList3 = new ArrayList(0);
        ArrayList arrayList4 = new ArrayList(0);
        HashSet hashSet = new HashSet();
        X xB = X.b();
        ArrayList arrayList5 = new ArrayList();
        Z zA = Z.a();
        ArrayList arrayList6 = new ArrayList(hashSet);
        C0163c0 c0163c0A = C0163c0.a(xB);
        ArrayList arrayList7 = new ArrayList(arrayList5);
        v0 v0Var = v0.b;
        ArrayMap arrayMap = new ArrayMap();
        ArrayMap arrayMap2 = zA.a;
        for (String str : arrayMap2.keySet()) {
            arrayMap.put(str, arrayMap2.get(str));
        }
        return new q0(arrayList, arrayList2, arrayList3, arrayList4, new F(arrayList6, c0163c0A, -1, arrayList7, false, new v0(arrayMap), null), null, null, null);
    }

    public final List b() {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            C0166e c0166e = (C0166e) it2.next();
            arrayList.add(c0166e.a);
            Iterator it3 = c0166e.b.iterator();
            while (it3.hasNext()) {
                arrayList.add((J) it3.next());
            }
        }
        return Collections.unmodifiableList(arrayList);
    }
}
