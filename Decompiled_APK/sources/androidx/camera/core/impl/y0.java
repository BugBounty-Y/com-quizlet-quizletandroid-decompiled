package androidx.camera.core.impl;

import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class y0 {
    public final LinkedHashMap a;

    public y0(String str) {
        this.a = new LinkedHashMap();
    }

    public static String e(int i, int i2, String str) {
        return i + '-' + i2 + '-' + str;
    }

    public p0 a() {
        p0 p0Var = new p0();
        ArrayList arrayList = new ArrayList();
        for (Map.Entry entry : this.a.entrySet()) {
            x0 x0Var = (x0) entry.getValue();
            if (x0Var.e) {
                p0Var.a(x0Var.a);
                arrayList.add((String) entry.getKey());
            }
        }
        arrayList.toString();
        AbstractC3053s1.f(3, "UseCaseAttachState");
        return p0Var;
    }

    public Collection b() {
        ArrayList arrayList = new ArrayList();
        for (Map.Entry entry : this.a.entrySet()) {
            if (((x0) entry.getValue()).e) {
                arrayList.add(((x0) entry.getValue()).a);
            }
        }
        return Collections.unmodifiableCollection(arrayList);
    }

    public Collection c() {
        ArrayList arrayList = new ArrayList();
        for (Map.Entry entry : this.a.entrySet()) {
            if (((x0) entry.getValue()).e) {
                arrayList.add(((x0) entry.getValue()).b);
            }
        }
        return Collections.unmodifiableCollection(arrayList);
    }

    public boolean d(String str) {
        LinkedHashMap linkedHashMap = this.a;
        if (linkedHashMap.containsKey(str)) {
            return ((x0) linkedHashMap.get(str)).e;
        }
        return false;
    }

    public androidx.work.impl.j f(androidx.work.impl.model.j id) {
        Intrinsics.checkNotNullParameter(id, "id");
        return (androidx.work.impl.j) this.a.remove(id);
    }

    public List g(String workSpecId) {
        Intrinsics.checkNotNullParameter(workSpecId, "workSpecId");
        LinkedHashMap linkedHashMap = this.a;
        LinkedHashMap linkedHashMap2 = new LinkedHashMap();
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            if (Intrinsics.b(((androidx.work.impl.model.j) entry.getKey()).a, workSpecId)) {
                linkedHashMap2.put(entry.getKey(), entry.getValue());
            }
        }
        Iterator it2 = linkedHashMap2.keySet().iterator();
        while (it2.hasNext()) {
            linkedHashMap.remove((androidx.work.impl.model.j) it2.next());
        }
        return CollectionsKt.w0(linkedHashMap2.values());
    }

    public androidx.work.impl.j h(androidx.work.impl.model.j id) {
        Intrinsics.checkNotNullParameter(id, "id");
        LinkedHashMap linkedHashMap = this.a;
        Object jVar = linkedHashMap.get(id);
        if (jVar == null) {
            jVar = new androidx.work.impl.j(id);
            linkedHashMap.put(id, jVar);
        }
        return (androidx.work.impl.j) jVar;
    }

    public void i(String str, q0 q0Var, A0 a0, C0168g c0168g, List list) {
        LinkedHashMap linkedHashMap = this.a;
        if (linkedHashMap.containsKey(str)) {
            x0 x0Var = new x0(q0Var, a0, c0168g, list);
            x0 x0Var2 = (x0) linkedHashMap.get(str);
            x0Var.e = x0Var2.e;
            x0Var.f = x0Var2.f;
            linkedHashMap.put(str, x0Var);
        }
    }

    public y0(int i) {
        switch (i) {
            case 2:
                this.a = new LinkedHashMap();
                break;
            default:
                this.a = new LinkedHashMap();
                break;
        }
    }
}
