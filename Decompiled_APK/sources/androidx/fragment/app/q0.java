package androidx.fragment.app;

import android.os.Bundle;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/* loaded from: classes.dex */
public final class q0 {
    public final ArrayList a = new ArrayList();
    public final HashMap b = new HashMap();
    public final HashMap c = new HashMap();
    public C1142k0 d;

    public final void a(Fragment fragment) {
        if (this.a.contains(fragment)) {
            throw new IllegalStateException("Fragment already added: " + fragment);
        }
        synchronized (this.a) {
            this.a.add(fragment);
        }
        fragment.mAdded = true;
    }

    public final Fragment b(String str) {
        o0 o0Var = (o0) this.b.get(str);
        if (o0Var != null) {
            return o0Var.c;
        }
        return null;
    }

    public final Fragment c(String str) {
        Fragment fragmentFindFragmentByWho;
        for (o0 o0Var : this.b.values()) {
            if (o0Var != null && (fragmentFindFragmentByWho = o0Var.c.findFragmentByWho(str)) != null) {
                return fragmentFindFragmentByWho;
            }
        }
        return null;
    }

    public final ArrayList d() {
        ArrayList arrayList = new ArrayList();
        for (o0 o0Var : this.b.values()) {
            if (o0Var != null) {
                arrayList.add(o0Var);
            }
        }
        return arrayList;
    }

    public final ArrayList e() {
        ArrayList arrayList = new ArrayList();
        for (o0 o0Var : this.b.values()) {
            if (o0Var != null) {
                arrayList.add(o0Var.c);
            } else {
                arrayList.add(null);
            }
        }
        return arrayList;
    }

    public final List f() {
        ArrayList arrayList;
        if (this.a.isEmpty()) {
            return Collections.EMPTY_LIST;
        }
        synchronized (this.a) {
            arrayList = new ArrayList(this.a);
        }
        return arrayList;
    }

    public final void g(o0 o0Var) {
        Fragment fragment = o0Var.c;
        String str = fragment.mWho;
        HashMap map = this.b;
        if (map.get(str) != null) {
            return;
        }
        map.put(fragment.mWho, o0Var);
        if (fragment.mRetainInstanceChangedWhileDetached) {
            if (fragment.mRetainInstance) {
                this.d.A(fragment);
            } else {
                this.d.C(fragment);
            }
            fragment.mRetainInstanceChangedWhileDetached = false;
        }
        if (AbstractC1136h0.N(2)) {
            fragment.toString();
        }
    }

    public final void h(o0 o0Var) {
        Fragment fragment = o0Var.c;
        if (fragment.mRetainInstance) {
            this.d.C(fragment);
        }
        HashMap map = this.b;
        if (map.get(fragment.mWho) == o0Var && ((o0) map.put(fragment.mWho, null)) != null && AbstractC1136h0.N(2)) {
            fragment.toString();
        }
    }

    public final Bundle i(Bundle bundle, String str) {
        HashMap map = this.c;
        return bundle != null ? (Bundle) map.put(str, bundle) : (Bundle) map.remove(str);
    }
}
