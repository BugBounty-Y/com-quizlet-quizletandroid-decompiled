package androidx.fragment.app;

import android.os.Bundle;
import android.os.Parcelable;
import android.util.Log;
import androidx.fragment.app.Fragment;
import androidx.viewpager.widget.ViewPager;
import java.util.ArrayList;

/* loaded from: classes.dex */
public abstract class p0 extends androidx.viewpager.widget.a {
    public final AbstractC1136h0 c;
    public final int d;
    public C1121a e = null;
    public final ArrayList f = new ArrayList();
    public final ArrayList g = new ArrayList();
    public Fragment h = null;
    public boolean i;

    public p0(int i, AbstractC1136h0 abstractC1136h0) {
        this.c = abstractC1136h0;
        this.d = i;
    }

    @Override // androidx.viewpager.widget.a
    public void a(ViewPager viewPager, int i, Object obj) {
        ArrayList arrayList;
        Fragment fragment = (Fragment) obj;
        C1121a c1121a = this.e;
        AbstractC1136h0 abstractC1136h0 = this.c;
        if (c1121a == null) {
            this.e = androidx.compose.ui.node.B.b(abstractC1136h0, abstractC1136h0);
        }
        while (true) {
            arrayList = this.f;
            if (arrayList.size() > i) {
                break;
            } else {
                arrayList.add(null);
            }
        }
        arrayList.set(i, fragment.isAdded() ? abstractC1136h0.d0(fragment) : null);
        this.g.set(i, null);
        this.e.k(fragment);
        if (fragment.equals(this.h)) {
            this.h = null;
        }
    }

    @Override // androidx.viewpager.widget.a
    public final void b() {
        C1121a c1121a = this.e;
        if (c1121a != null) {
            if (!this.i) {
                try {
                    this.i = true;
                    if (c1121a.g) {
                        throw new IllegalStateException("This transaction is already being added to the back stack");
                    }
                    c1121a.h = false;
                    c1121a.r.B(c1121a, true);
                } finally {
                    this.i = false;
                }
            }
            this.e = null;
        }
    }

    @Override // androidx.viewpager.widget.a
    public Object f(ViewPager viewPager, int i) {
        Fragment.SavedState savedState;
        Fragment fragment;
        ArrayList arrayList = this.g;
        if (arrayList.size() > i && (fragment = (Fragment) arrayList.get(i)) != null) {
            return fragment;
        }
        if (this.e == null) {
            AbstractC1136h0 abstractC1136h0 = this.c;
            this.e = androidx.compose.ui.node.B.b(abstractC1136h0, abstractC1136h0);
        }
        Fragment fragmentJ = j(i);
        ArrayList arrayList2 = this.f;
        if (arrayList2.size() > i && (savedState = (Fragment.SavedState) arrayList2.get(i)) != null) {
            fragmentJ.setInitialSavedState(savedState);
        }
        while (arrayList.size() <= i) {
            arrayList.add(null);
        }
        fragmentJ.setMenuVisibility(false);
        int i2 = this.d;
        if (i2 == 0) {
            fragmentJ.setUserVisibleHint(false);
        }
        arrayList.set(i, fragmentJ);
        this.e.i(viewPager.getId(), fragmentJ, null, 1);
        if (i2 == 1) {
            this.e.n(fragmentJ, androidx.lifecycle.B.d);
        }
        return fragmentJ;
    }

    @Override // androidx.viewpager.widget.a
    public final void g(Parcelable parcelable, ClassLoader classLoader) throws NumberFormatException {
        Fragment fragmentB;
        if (parcelable != null) {
            Bundle bundle = (Bundle) parcelable;
            bundle.setClassLoader(classLoader);
            Parcelable[] parcelableArray = bundle.getParcelableArray("states");
            ArrayList arrayList = this.f;
            arrayList.clear();
            ArrayList arrayList2 = this.g;
            arrayList2.clear();
            if (parcelableArray != null) {
                for (Parcelable parcelable2 : parcelableArray) {
                    arrayList.add((Fragment.SavedState) parcelable2);
                }
            }
            for (String str : bundle.keySet()) {
                if (str.startsWith("f")) {
                    int i = Integer.parseInt(str.substring(1));
                    AbstractC1136h0 abstractC1136h0 = this.c;
                    abstractC1136h0.getClass();
                    String string = bundle.getString(str);
                    if (string == null) {
                        fragmentB = null;
                    } else {
                        fragmentB = abstractC1136h0.c.b(string);
                        if (fragmentB == null) {
                            abstractC1136h0.l0(new IllegalStateException(android.support.v4.media.session.a.m("Fragment no longer exists for key ", str, ": unique id ", string)));
                            throw null;
                        }
                    }
                    if (fragmentB != null) {
                        while (arrayList2.size() <= i) {
                            arrayList2.add(null);
                        }
                        fragmentB.setMenuVisibility(false);
                        arrayList2.set(i, fragmentB);
                    } else {
                        Log.w("FragmentStatePagerAdapt", "Bad fragment at key ".concat(str));
                    }
                }
            }
        }
    }

    @Override // androidx.viewpager.widget.a
    public final Bundle h() {
        Bundle bundle;
        ArrayList arrayList = this.f;
        if (arrayList.size() > 0) {
            bundle = new Bundle();
            Fragment.SavedState[] savedStateArr = new Fragment.SavedState[arrayList.size()];
            arrayList.toArray(savedStateArr);
            bundle.putParcelableArray("states", savedStateArr);
        } else {
            bundle = null;
        }
        int i = 0;
        while (true) {
            ArrayList arrayList2 = this.g;
            if (i >= arrayList2.size()) {
                return bundle;
            }
            Fragment fragment = (Fragment) arrayList2.get(i);
            if (fragment != null && fragment.isAdded()) {
                if (bundle == null) {
                    bundle = new Bundle();
                }
                String strF = android.support.v4.media.session.a.f(i, "f");
                AbstractC1136h0 abstractC1136h0 = this.c;
                abstractC1136h0.getClass();
                if (fragment.mFragmentManager != abstractC1136h0) {
                    abstractC1136h0.l0(new IllegalStateException(androidx.compose.ui.node.B.g("Fragment ", fragment, " is not currently in the FragmentManager")));
                    throw null;
                }
                bundle.putString(strF, fragment.mWho);
            }
            i++;
        }
    }

    @Override // androidx.viewpager.widget.a
    public final void i(ViewPager viewPager) {
        if (viewPager.getId() != -1) {
            return;
        }
        throw new IllegalStateException("ViewPager with adapter " + this + " requires a view id");
    }

    public abstract Fragment j(int i);
}
