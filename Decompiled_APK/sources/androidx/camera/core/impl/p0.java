package androidx.camera.core.impl;

import android.hardware.camera2.params.InputConfiguration;
import android.util.Range;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/* loaded from: classes.dex */
public final class p0 extends l0 {
    public final androidx.camera.camera2.internal.compat.workaround.e i = new androidx.camera.camera2.internal.compat.workaround.e(3);
    public boolean j = true;
    public boolean k = false;
    public final ArrayList l = new ArrayList();

    public final void a(q0 q0Var) {
        Object objE;
        F f = q0Var.g;
        int i = f.c;
        androidx.camera.core.a0 a0Var = this.b;
        if (i != -1) {
            this.k = true;
            int i2 = a0Var.a;
            Integer numValueOf = Integer.valueOf(i);
            List list = q0.i;
            if (list.indexOf(numValueOf) < list.indexOf(Integer.valueOf(i2))) {
                i = i2;
            }
            a0Var.a = i;
        }
        C0162c c0162c = F.j;
        Object objE2 = C0168g.f;
        C0163c0 c0163c0 = f.b;
        try {
            objE2 = c0163c0.e(c0162c);
        } catch (IllegalArgumentException unused) {
        }
        Range range = (Range) objE2;
        Objects.requireNonNull(range);
        Range range2 = C0168g.f;
        if (!range.equals(range2)) {
            X x = (X) a0Var.d;
            C0162c c0162c2 = F.j;
            x.getClass();
            try {
                objE = x.e(c0162c2);
            } catch (IllegalArgumentException unused2) {
                objE = range2;
            }
            if (((Range) objE).equals(range2)) {
                ((X) a0Var.d).m(F.j, range);
            } else {
                X x2 = (X) a0Var.d;
                C0162c c0162c3 = F.j;
                Object objE3 = C0168g.f;
                x2.getClass();
                try {
                    objE3 = x2.e(c0162c3);
                } catch (IllegalArgumentException unused3) {
                }
                if (!((Range) objE3).equals(range)) {
                    this.j = false;
                    AbstractC3053s1.f(3, "ValidatingBuilder");
                }
            }
        }
        int iA = f.a();
        if (iA != 0) {
            a0Var.getClass();
            if (iA != 0) {
                ((X) a0Var.d).m(A0.w0, Integer.valueOf(iA));
            }
        }
        int iB = f.b();
        if (iB != 0) {
            a0Var.getClass();
            if (iB != 0) {
                ((X) a0Var.d).m(A0.x0, Integer.valueOf(iB));
            }
        }
        F f2 = q0Var.g;
        ((Z) a0Var.f).a.putAll((Map) f2.f.a);
        this.c.addAll(q0Var.c);
        this.d.addAll(q0Var.d);
        a0Var.a(f2.d);
        this.e.addAll(q0Var.e);
        o0 o0Var = q0Var.f;
        if (o0Var != null) {
            this.l.add(o0Var);
        }
        InputConfiguration inputConfiguration = q0Var.h;
        if (inputConfiguration != null) {
            this.g = inputConfiguration;
        }
        LinkedHashSet<C0166e> linkedHashSet = this.a;
        linkedHashSet.addAll(q0Var.a);
        HashSet hashSet = (HashSet) a0Var.c;
        hashSet.addAll(Collections.unmodifiableList(f.a));
        ArrayList arrayList = new ArrayList();
        for (C0166e c0166e : linkedHashSet) {
            arrayList.add(c0166e.a);
            Iterator it2 = c0166e.b.iterator();
            while (it2.hasNext()) {
                arrayList.add((J) it2.next());
            }
        }
        if (!arrayList.containsAll(hashSet)) {
            AbstractC3053s1.f(3, "ValidatingBuilder");
            this.j = false;
        }
        C0166e c0166e2 = q0Var.b;
        if (c0166e2 != null) {
            C0166e c0166e3 = this.h;
            if (c0166e3 == c0166e2 || c0166e3 == null) {
                this.h = c0166e2;
            } else {
                AbstractC3053s1.f(3, "ValidatingBuilder");
                this.j = false;
            }
        }
        a0Var.d(c0163c0);
    }

    public final q0 b() {
        if (!this.j) {
            throw new IllegalArgumentException("Unsupported session configuration combination");
        }
        ArrayList arrayList = new ArrayList(this.a);
        androidx.camera.camera2.internal.compat.workaround.e eVar = this.i;
        if (eVar.b) {
            Collections.sort(arrayList, new androidx.camera.core.internal.compat.workaround.a(eVar, 0));
        }
        return new q0(arrayList, new ArrayList(this.c), new ArrayList(this.d), new ArrayList(this.e), this.b.e(), !this.l.isEmpty() ? new androidx.camera.camera2.internal.Z(this, 4) : null, this.g, this.h);
    }
}
