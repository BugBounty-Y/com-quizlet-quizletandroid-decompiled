package androidx.fragment.app;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

/* renamed from: androidx.fragment.app.k0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1142k0 extends androidx.lifecycle.w0 {
    public static final C1140j0 h = new C1140j0();
    public final boolean e;
    public final HashMap b = new HashMap();
    public final HashMap c = new HashMap();
    public final HashMap d = new HashMap();
    public boolean f = false;
    public boolean g = false;

    public C1142k0(boolean z) {
        this.e = z;
    }

    public final void A(Fragment fragment) {
        if (this.g) {
            AbstractC1136h0.N(2);
            return;
        }
        HashMap map = this.b;
        if (map.containsKey(fragment.mWho)) {
            return;
        }
        map.put(fragment.mWho, fragment);
        if (AbstractC1136h0.N(2)) {
            fragment.toString();
        }
    }

    public final void B(String str, boolean z) {
        HashMap map = this.c;
        C1142k0 c1142k0 = (C1142k0) map.get(str);
        if (c1142k0 != null) {
            if (z) {
                ArrayList arrayList = new ArrayList();
                arrayList.addAll(c1142k0.c.keySet());
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    String str2 = (String) it2.next();
                    AbstractC1136h0.N(3);
                    c1142k0.B(str2, true);
                }
            }
            c1142k0.z();
            map.remove(str);
        }
        HashMap map2 = this.d;
        androidx.lifecycle.B0 b0 = (androidx.lifecycle.B0) map2.get(str);
        if (b0 != null) {
            b0.a();
            map2.remove(str);
        }
    }

    public final void C(Fragment fragment) {
        if (this.g) {
            AbstractC1136h0.N(2);
        } else {
            if (this.b.remove(fragment.mWho) == null || !AbstractC1136h0.N(2)) {
                return;
            }
            fragment.toString();
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C1142k0.class == obj.getClass()) {
            C1142k0 c1142k0 = (C1142k0) obj;
            if (this.b.equals(c1142k0.b) && this.c.equals(c1142k0.c) && this.d.equals(c1142k0.d)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FragmentManagerViewModel{");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append("} Fragments (");
        Iterator it2 = this.b.values().iterator();
        while (it2.hasNext()) {
            sb.append(it2.next());
            if (it2.hasNext()) {
                sb.append(", ");
            }
        }
        sb.append(") Child Non Config (");
        Iterator it3 = this.c.keySet().iterator();
        while (it3.hasNext()) {
            sb.append((String) it3.next());
            if (it3.hasNext()) {
                sb.append(", ");
            }
        }
        sb.append(") ViewModelStores (");
        Iterator it4 = this.d.keySet().iterator();
        while (it4.hasNext()) {
            sb.append((String) it4.next());
            if (it4.hasNext()) {
                sb.append(", ");
            }
        }
        sb.append(')');
        return sb.toString();
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        if (AbstractC1136h0.N(3)) {
            toString();
        }
        this.f = true;
    }
}
