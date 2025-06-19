package androidx.fragment.app;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.Configuration;
import android.os.Bundle;
import android.os.Looper;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.core.app.C1023j;
import androidx.core.view.InterfaceC1056m;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.mlkit_vision_camera.C1;
import com.quizlet.quizletandroid.R;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.fragment.app.h0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1136h0 {
    public Fragment A;
    public androidx.activity.result.g D;
    public androidx.activity.result.g E;
    public androidx.activity.result.g F;
    public boolean H;
    public boolean I;
    public boolean J;
    public boolean K;
    public boolean L;
    public ArrayList M;
    public ArrayList N;
    public ArrayList O;
    public C1142k0 P;
    public boolean b;
    public ArrayList e;
    public androidx.activity.L g;
    public final T r;
    public final T s;
    public final T t;
    public final T u;
    public O x;
    public L y;
    public Fragment z;
    public final ArrayList a = new ArrayList();
    public final q0 c = new q0();
    public ArrayList d = new ArrayList();
    public final Q f = new Q(this);
    public C1121a h = null;
    public boolean i = false;
    public final V j = new V(this);
    public final AtomicInteger k = new AtomicInteger();
    public final Map l = Collections.synchronizedMap(new HashMap());
    public final Map m = Collections.synchronizedMap(new HashMap());
    public final Map n = Collections.synchronizedMap(new HashMap());
    public final ArrayList o = new ArrayList();
    public final J p = new J(this);
    public final CopyOnWriteArrayList q = new CopyOnWriteArrayList();
    public final W v = new W(this);
    public int w = -1;
    public final X B = new X(this);
    public final Y C = new Y();
    public ArrayDeque G = new ArrayDeque();
    public final B0 Q = new B0(this, 3);

    /* JADX WARN: Type inference failed for: r0v17, types: [androidx.fragment.app.T] */
    /* JADX WARN: Type inference failed for: r0v18, types: [androidx.fragment.app.T] */
    /* JADX WARN: Type inference failed for: r0v19, types: [androidx.fragment.app.T] */
    /* JADX WARN: Type inference failed for: r0v20, types: [androidx.fragment.app.T] */
    public AbstractC1136h0() {
        final int i = 0;
        this.r = new androidx.core.util.a() { // from class: androidx.fragment.app.T
            @Override // androidx.core.util.a
            public final void accept(Object obj) {
                switch (i) {
                    case 0:
                        Configuration configuration = (Configuration) obj;
                        AbstractC1136h0 abstractC1136h0 = this;
                        if (abstractC1136h0.P()) {
                            abstractC1136h0.j(false, configuration);
                            break;
                        }
                        break;
                    case 1:
                        Integer num = (Integer) obj;
                        AbstractC1136h0 abstractC1136h02 = this;
                        if (abstractC1136h02.P() && num.intValue() == 80) {
                            abstractC1136h02.n(false);
                            break;
                        }
                        break;
                    case 2:
                        C1023j c1023j = (C1023j) obj;
                        AbstractC1136h0 abstractC1136h03 = this;
                        if (abstractC1136h03.P()) {
                            abstractC1136h03.o(c1023j.a, false);
                            break;
                        }
                        break;
                    default:
                        androidx.core.app.S s = (androidx.core.app.S) obj;
                        AbstractC1136h0 abstractC1136h04 = this;
                        if (abstractC1136h04.P()) {
                            abstractC1136h04.t(s.a, false);
                            break;
                        }
                        break;
                }
            }
        };
        final int i2 = 1;
        this.s = new androidx.core.util.a() { // from class: androidx.fragment.app.T
            @Override // androidx.core.util.a
            public final void accept(Object obj) {
                switch (i2) {
                    case 0:
                        Configuration configuration = (Configuration) obj;
                        AbstractC1136h0 abstractC1136h0 = this;
                        if (abstractC1136h0.P()) {
                            abstractC1136h0.j(false, configuration);
                            break;
                        }
                        break;
                    case 1:
                        Integer num = (Integer) obj;
                        AbstractC1136h0 abstractC1136h02 = this;
                        if (abstractC1136h02.P() && num.intValue() == 80) {
                            abstractC1136h02.n(false);
                            break;
                        }
                        break;
                    case 2:
                        C1023j c1023j = (C1023j) obj;
                        AbstractC1136h0 abstractC1136h03 = this;
                        if (abstractC1136h03.P()) {
                            abstractC1136h03.o(c1023j.a, false);
                            break;
                        }
                        break;
                    default:
                        androidx.core.app.S s = (androidx.core.app.S) obj;
                        AbstractC1136h0 abstractC1136h04 = this;
                        if (abstractC1136h04.P()) {
                            abstractC1136h04.t(s.a, false);
                            break;
                        }
                        break;
                }
            }
        };
        final int i3 = 2;
        this.t = new androidx.core.util.a() { // from class: androidx.fragment.app.T
            @Override // androidx.core.util.a
            public final void accept(Object obj) {
                switch (i3) {
                    case 0:
                        Configuration configuration = (Configuration) obj;
                        AbstractC1136h0 abstractC1136h0 = this;
                        if (abstractC1136h0.P()) {
                            abstractC1136h0.j(false, configuration);
                            break;
                        }
                        break;
                    case 1:
                        Integer num = (Integer) obj;
                        AbstractC1136h0 abstractC1136h02 = this;
                        if (abstractC1136h02.P() && num.intValue() == 80) {
                            abstractC1136h02.n(false);
                            break;
                        }
                        break;
                    case 2:
                        C1023j c1023j = (C1023j) obj;
                        AbstractC1136h0 abstractC1136h03 = this;
                        if (abstractC1136h03.P()) {
                            abstractC1136h03.o(c1023j.a, false);
                            break;
                        }
                        break;
                    default:
                        androidx.core.app.S s = (androidx.core.app.S) obj;
                        AbstractC1136h0 abstractC1136h04 = this;
                        if (abstractC1136h04.P()) {
                            abstractC1136h04.t(s.a, false);
                            break;
                        }
                        break;
                }
            }
        };
        final int i4 = 3;
        this.u = new androidx.core.util.a() { // from class: androidx.fragment.app.T
            @Override // androidx.core.util.a
            public final void accept(Object obj) {
                switch (i4) {
                    case 0:
                        Configuration configuration = (Configuration) obj;
                        AbstractC1136h0 abstractC1136h0 = this;
                        if (abstractC1136h0.P()) {
                            abstractC1136h0.j(false, configuration);
                            break;
                        }
                        break;
                    case 1:
                        Integer num = (Integer) obj;
                        AbstractC1136h0 abstractC1136h02 = this;
                        if (abstractC1136h02.P() && num.intValue() == 80) {
                            abstractC1136h02.n(false);
                            break;
                        }
                        break;
                    case 2:
                        C1023j c1023j = (C1023j) obj;
                        AbstractC1136h0 abstractC1136h03 = this;
                        if (abstractC1136h03.P()) {
                            abstractC1136h03.o(c1023j.a, false);
                            break;
                        }
                        break;
                    default:
                        androidx.core.app.S s = (androidx.core.app.S) obj;
                        AbstractC1136h0 abstractC1136h04 = this;
                        if (abstractC1136h04.P()) {
                            abstractC1136h04.t(s.a, false);
                            break;
                        }
                        break;
                }
            }
        };
    }

    public static AbstractC1136h0 F(View view) {
        I i;
        Fragment fragmentG = G(view);
        if (fragmentG != null) {
            if (fragmentG.isAdded()) {
                return fragmentG.getChildFragmentManager();
            }
            throw new IllegalStateException("The Fragment " + fragmentG + " that owns View " + view + " has already been destroyed. Nested fragments should always use the child FragmentManager.");
        }
        Context context = view.getContext();
        while (true) {
            if (!(context instanceof ContextWrapper)) {
                i = null;
                break;
            }
            if (context instanceof I) {
                i = (I) context;
                break;
            }
            context = ((ContextWrapper) context).getBaseContext();
        }
        if (i != null) {
            return i.getSupportFragmentManager();
        }
        throw new IllegalStateException("View " + view + " is not within a subclass of FragmentActivity.");
    }

    public static Fragment G(View view) {
        while (view != null) {
            Object tag = view.getTag(R.id.fragment_container_view_tag);
            Fragment fragment = tag instanceof Fragment ? (Fragment) tag : null;
            if (fragment != null) {
                return fragment;
            }
            Object parent = view.getParent();
            view = parent instanceof View ? (View) parent : null;
        }
        return null;
    }

    public static HashSet I(C1121a c1121a) {
        HashSet hashSet = new HashSet();
        for (int i = 0; i < c1121a.a.size(); i++) {
            Fragment fragment = ((r0) c1121a.a.get(i)).b;
            if (fragment != null && c1121a.g) {
                hashSet.add(fragment);
            }
        }
        return hashSet;
    }

    public static boolean N(int i) {
        return Log.isLoggable("FragmentManager", i);
    }

    public static boolean O(Fragment fragment) {
        if (fragment.mHasMenu && fragment.mMenuVisible) {
            return true;
        }
        Iterator it2 = fragment.mChildFragmentManager.c.e().iterator();
        boolean zO = false;
        while (it2.hasNext()) {
            Fragment fragment2 = (Fragment) it2.next();
            if (fragment2 != null) {
                zO = O(fragment2);
            }
            if (zO) {
                return true;
            }
        }
        return false;
    }

    public static boolean Q(Fragment fragment) {
        if (fragment == null) {
            return true;
        }
        AbstractC1136h0 abstractC1136h0 = fragment.mFragmentManager;
        return fragment.equals(abstractC1136h0.A) && Q(abstractC1136h0.z);
    }

    public final boolean A(boolean z) {
        boolean zA;
        C1121a c1121a;
        z(z);
        if (!this.i && (c1121a = this.h) != null) {
            c1121a.s = false;
            c1121a.f();
            if (N(3)) {
                Objects.toString(this.h);
                Objects.toString(this.a);
            }
            this.h.h(false, false);
            this.a.add(0, this.h);
            Iterator it2 = this.h.a.iterator();
            while (it2.hasNext()) {
                Fragment fragment = ((r0) it2.next()).b;
                if (fragment != null) {
                    fragment.mTransitioning = false;
                }
            }
            this.h = null;
        }
        boolean z2 = false;
        while (true) {
            ArrayList arrayList = this.M;
            ArrayList arrayList2 = this.N;
            synchronized (this.a) {
                if (this.a.isEmpty()) {
                    zA = false;
                } else {
                    try {
                        int size = this.a.size();
                        zA = false;
                        for (int i = 0; i < size; i++) {
                            zA |= ((InterfaceC1130e0) this.a.get(i)).a(arrayList, arrayList2);
                        }
                    } finally {
                    }
                }
            }
            if (!zA) {
                break;
            }
            this.b = true;
            try {
                a0(this.M, this.N);
                e();
                z2 = true;
            } catch (Throwable th) {
                e();
                throw th;
            }
        }
        m0();
        if (this.L) {
            this.L = false;
            Iterator it3 = this.c.d().iterator();
            while (it3.hasNext()) {
                o0 o0Var = (o0) it3.next();
                Fragment fragment2 = o0Var.c;
                if (fragment2.mDeferStart) {
                    if (this.b) {
                        this.L = true;
                    } else {
                        fragment2.mDeferStart = false;
                        o0Var.i();
                    }
                }
            }
        }
        this.c.b.values().removeAll(Collections.singleton(null));
        return z2;
    }

    public final void B(C1121a c1121a, boolean z) {
        if (z && (this.x == null || this.K)) {
            return;
        }
        z(z);
        C1121a c1121a2 = this.h;
        if (c1121a2 != null) {
            c1121a2.s = false;
            c1121a2.f();
            if (N(3)) {
                Objects.toString(this.h);
                Objects.toString(c1121a);
            }
            this.h.h(false, false);
            this.h.a(this.M, this.N);
            Iterator it2 = this.h.a.iterator();
            while (it2.hasNext()) {
                Fragment fragment = ((r0) it2.next()).b;
                if (fragment != null) {
                    fragment.mTransitioning = false;
                }
            }
            this.h = null;
        }
        c1121a.a(this.M, this.N);
        this.b = true;
        try {
            a0(this.M, this.N);
            e();
            m0();
            boolean z2 = this.L;
            q0 q0Var = this.c;
            if (z2) {
                this.L = false;
                Iterator it3 = q0Var.d().iterator();
                while (it3.hasNext()) {
                    o0 o0Var = (o0) it3.next();
                    Fragment fragment2 = o0Var.c;
                    if (fragment2.mDeferStart) {
                        if (this.b) {
                            this.L = true;
                        } else {
                            fragment2.mDeferStart = false;
                            o0Var.i();
                        }
                    }
                }
            }
            q0Var.b.values().removeAll(Collections.singleton(null));
        } catch (Throwable th) {
            e();
            throw th;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:109:0x0239 A[PHI: r14
  0x0239: PHI (r14v19 int) = (r14v18 int), (r14v20 int) binds: [B:102:0x0229, B:107:0x0235] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0186  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void C(java.util.ArrayList r29, java.util.ArrayList r30, int r31, int r32) {
        /*
            Method dump skipped, instructions count: 1620
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.fragment.app.AbstractC1136h0.C(java.util.ArrayList, java.util.ArrayList, int, int):void");
    }

    public final Fragment D(int i) {
        q0 q0Var = this.c;
        ArrayList arrayList = q0Var.a;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            Fragment fragment = (Fragment) arrayList.get(size);
            if (fragment != null && fragment.mFragmentId == i) {
                return fragment;
            }
        }
        for (o0 o0Var : q0Var.b.values()) {
            if (o0Var != null) {
                Fragment fragment2 = o0Var.c;
                if (fragment2.mFragmentId == i) {
                    return fragment2;
                }
            }
        }
        return null;
    }

    public final Fragment E(String str) {
        q0 q0Var = this.c;
        if (str != null) {
            ArrayList arrayList = q0Var.a;
            for (int size = arrayList.size() - 1; size >= 0; size--) {
                Fragment fragment = (Fragment) arrayList.get(size);
                if (fragment != null && str.equals(fragment.mTag)) {
                    return fragment;
                }
            }
        }
        if (str == null) {
            q0Var.getClass();
            return null;
        }
        for (o0 o0Var : q0Var.b.values()) {
            if (o0Var != null) {
                Fragment fragment2 = o0Var.c;
                if (str.equals(fragment2.mTag)) {
                    return fragment2;
                }
            }
        }
        return null;
    }

    public final void H() {
        Iterator it2 = f().iterator();
        while (it2.hasNext()) {
            C1147o c1147o = (C1147o) it2.next();
            if (c1147o.f) {
                N(2);
                c1147o.f = false;
                c1147o.e();
            }
        }
    }

    public final int J() {
        return this.d.size() + (this.h != null ? 1 : 0);
    }

    public final ViewGroup K(Fragment fragment) {
        ViewGroup viewGroup = fragment.mContainer;
        if (viewGroup != null) {
            return viewGroup;
        }
        if (fragment.mContainerId <= 0 || !this.y.c()) {
            return null;
        }
        View viewB = this.y.b(fragment.mContainerId);
        if (viewB instanceof ViewGroup) {
            return (ViewGroup) viewB;
        }
        return null;
    }

    public final N L() {
        Fragment fragment = this.z;
        return fragment != null ? fragment.mFragmentManager.L() : this.B;
    }

    public final Y M() {
        Fragment fragment = this.z;
        return fragment != null ? fragment.mFragmentManager.M() : this.C;
    }

    public final boolean P() {
        Fragment fragment = this.z;
        if (fragment == null) {
            return true;
        }
        return fragment.isAdded() && this.z.getParentFragmentManager().P();
    }

    public final boolean R() {
        return this.I || this.J;
    }

    public final void S(int i, boolean z) {
        HashMap map;
        O o;
        if (this.x == null && i != -1) {
            throw new IllegalStateException("No activity");
        }
        if (z || i != this.w) {
            this.w = i;
            q0 q0Var = this.c;
            Iterator it2 = q0Var.a.iterator();
            while (true) {
                boolean zHasNext = it2.hasNext();
                map = q0Var.b;
                if (!zHasNext) {
                    break;
                }
                o0 o0Var = (o0) map.get(((Fragment) it2.next()).mWho);
                if (o0Var != null) {
                    o0Var.i();
                }
            }
            for (o0 o0Var2 : map.values()) {
                if (o0Var2 != null) {
                    o0Var2.i();
                    Fragment fragment = o0Var2.c;
                    if (fragment.mRemoving && !fragment.isInBackStack()) {
                        if (fragment.mBeingSaved && !q0Var.c.containsKey(fragment.mWho)) {
                            q0Var.i(o0Var2.l(), fragment.mWho);
                        }
                        q0Var.h(o0Var2);
                    }
                }
            }
            Iterator it3 = q0Var.d().iterator();
            while (it3.hasNext()) {
                o0 o0Var3 = (o0) it3.next();
                Fragment fragment2 = o0Var3.c;
                if (fragment2.mDeferStart) {
                    if (this.b) {
                        this.L = true;
                    } else {
                        fragment2.mDeferStart = false;
                        o0Var3.i();
                    }
                }
            }
            if (this.H && (o = this.x) != null && this.w == 7) {
                ((H) o).e.invalidateMenu();
                this.H = false;
            }
        }
    }

    public final void T() {
        if (this.x == null) {
            return;
        }
        this.I = false;
        this.J = false;
        this.P.g = false;
        for (Fragment fragment : this.c.f()) {
            if (fragment != null) {
                fragment.noteStateNotSaved();
            }
        }
    }

    public final void U(FragmentContainerView fragmentContainerView) {
        View view;
        Iterator it2 = this.c.d().iterator();
        while (it2.hasNext()) {
            o0 o0Var = (o0) it2.next();
            Fragment fragment = o0Var.c;
            if (fragment.mContainerId == fragmentContainerView.getId() && (view = fragment.mView) != null && view.getParent() == null) {
                fragment.mContainer = fragmentContainerView;
                o0Var.a();
                o0Var.i();
            }
        }
    }

    public final void V() {
        y(new C1132f0(this, null, -1, 0), false);
    }

    public final boolean W() {
        return X(-1, 0);
    }

    public final boolean X(int i, int i2) {
        A(false);
        z(true);
        Fragment fragment = this.A;
        if (fragment != null && i < 0 && fragment.getChildFragmentManager().W()) {
            return true;
        }
        boolean zY = Y(this.M, this.N, null, i, i2);
        if (zY) {
            this.b = true;
            try {
                a0(this.M, this.N);
            } finally {
                e();
            }
        }
        m0();
        boolean z = this.L;
        q0 q0Var = this.c;
        if (z) {
            this.L = false;
            Iterator it2 = q0Var.d().iterator();
            while (it2.hasNext()) {
                o0 o0Var = (o0) it2.next();
                Fragment fragment2 = o0Var.c;
                if (fragment2.mDeferStart) {
                    if (this.b) {
                        this.L = true;
                    } else {
                        fragment2.mDeferStart = false;
                        o0Var.i();
                    }
                }
            }
        }
        q0Var.b.values().removeAll(Collections.singleton(null));
        return zY;
    }

    public final boolean Y(ArrayList arrayList, ArrayList arrayList2, String str, int i, int i2) {
        boolean z = (i2 & 1) != 0;
        int size = -1;
        if (!this.d.isEmpty()) {
            if (str != null || i >= 0) {
                int size2 = this.d.size() - 1;
                while (size2 >= 0) {
                    C1121a c1121a = (C1121a) this.d.get(size2);
                    if ((str != null && str.equals(c1121a.i)) || (i >= 0 && i == c1121a.t)) {
                        break;
                    }
                    size2--;
                }
                if (size2 < 0) {
                    size = size2;
                } else if (z) {
                    size = size2;
                    while (size > 0) {
                        C1121a c1121a2 = (C1121a) this.d.get(size - 1);
                        if ((str == null || !str.equals(c1121a2.i)) && (i < 0 || i != c1121a2.t)) {
                            break;
                        }
                        size--;
                    }
                } else if (size2 != this.d.size() - 1) {
                    size = size2 + 1;
                }
            } else {
                size = z ? 0 : this.d.size() - 1;
            }
        }
        if (size < 0) {
            return false;
        }
        for (int size3 = this.d.size() - 1; size3 >= size; size3--) {
            arrayList.add((C1121a) this.d.remove(size3));
            arrayList2.add(Boolean.TRUE);
        }
        return true;
    }

    public final void Z(Fragment fragment) {
        if (N(2)) {
            Objects.toString(fragment);
        }
        boolean zIsInBackStack = fragment.isInBackStack();
        if (fragment.mDetached && zIsInBackStack) {
            return;
        }
        q0 q0Var = this.c;
        synchronized (q0Var.a) {
            q0Var.a.remove(fragment);
        }
        fragment.mAdded = false;
        if (O(fragment)) {
            this.H = true;
        }
        fragment.mRemoving = true;
        k0(fragment);
    }

    public final o0 a(Fragment fragment) {
        String str = fragment.mPreviousWho;
        if (str != null) {
            androidx.fragment.app.strictmode.c.c(fragment, str);
        }
        if (N(2)) {
            fragment.toString();
        }
        o0 o0VarH = h(fragment);
        fragment.mFragmentManager = this;
        q0 q0Var = this.c;
        q0Var.g(o0VarH);
        if (!fragment.mDetached) {
            q0Var.a(fragment);
            fragment.mRemoving = false;
            if (fragment.mView == null) {
                fragment.mHiddenChanged = false;
            }
            if (O(fragment)) {
                this.H = true;
            }
        }
        return o0VarH;
    }

    public final void a0(ArrayList arrayList, ArrayList arrayList2) {
        if (arrayList.isEmpty()) {
            return;
        }
        if (arrayList.size() != arrayList2.size()) {
            throw new IllegalStateException("Internal error with the back stack records");
        }
        int size = arrayList.size();
        int i = 0;
        int i2 = 0;
        while (i < size) {
            if (!((C1121a) arrayList.get(i)).p) {
                if (i2 != i) {
                    C(arrayList, arrayList2, i2, i);
                }
                i2 = i + 1;
                if (((Boolean) arrayList2.get(i)).booleanValue()) {
                    while (i2 < size && ((Boolean) arrayList2.get(i2)).booleanValue() && !((C1121a) arrayList.get(i2)).p) {
                        i2++;
                    }
                }
                C(arrayList, arrayList2, i, i2);
                i = i2 - 1;
            }
            i++;
        }
        if (i2 != size) {
            C(arrayList, arrayList2, i2, size);
        }
    }

    public final void b(InterfaceC1144l0 interfaceC1144l0) {
        this.q.add(interfaceC1144l0);
    }

    public final void b0(Bundle bundle) {
        J j;
        o0 o0Var;
        Bundle bundle2;
        Bundle bundle3;
        for (String str : bundle.keySet()) {
            if (str.startsWith("result_") && (bundle3 = bundle.getBundle(str)) != null) {
                bundle3.setClassLoader(this.x.b.getClassLoader());
                this.m.put(str.substring(7), bundle3);
            }
        }
        HashMap map = new HashMap();
        for (String str2 : bundle.keySet()) {
            if (str2.startsWith("fragment_") && (bundle2 = bundle.getBundle(str2)) != null) {
                bundle2.setClassLoader(this.x.b.getClassLoader());
                map.put(str2.substring(9), bundle2);
            }
        }
        q0 q0Var = this.c;
        HashMap map2 = q0Var.c;
        map2.clear();
        map2.putAll(map);
        FragmentManagerState fragmentManagerState = (FragmentManagerState) bundle.getParcelable("state");
        if (fragmentManagerState == null) {
            return;
        }
        HashMap map3 = q0Var.b;
        map3.clear();
        Iterator it2 = fragmentManagerState.a.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            j = this.p;
            if (!zHasNext) {
                break;
            }
            Bundle bundleI = q0Var.i(null, (String) it2.next());
            if (bundleI != null) {
                Fragment fragment = (Fragment) this.P.b.get(((FragmentState) bundleI.getParcelable("state")).b);
                if (fragment != null) {
                    if (N(2)) {
                        fragment.toString();
                    }
                    o0Var = new o0(j, q0Var, fragment, bundleI);
                } else {
                    o0Var = new o0(this.p, this.c, this.x.b.getClassLoader(), L(), bundleI);
                }
                Fragment fragment2 = o0Var.c;
                fragment2.mSavedFragmentState = bundleI;
                fragment2.mFragmentManager = this;
                if (N(2)) {
                    fragment2.toString();
                }
                o0Var.j(this.x.b.getClassLoader());
                q0Var.g(o0Var);
                o0Var.e = this.w;
            }
        }
        C1142k0 c1142k0 = this.P;
        c1142k0.getClass();
        Iterator it3 = new ArrayList(c1142k0.b.values()).iterator();
        while (it3.hasNext()) {
            Fragment fragment3 = (Fragment) it3.next();
            if (map3.get(fragment3.mWho) == null) {
                if (N(2)) {
                    fragment3.toString();
                    Objects.toString(fragmentManagerState.a);
                }
                this.P.C(fragment3);
                fragment3.mFragmentManager = this;
                o0 o0Var2 = new o0(j, q0Var, fragment3);
                o0Var2.e = 1;
                o0Var2.i();
                fragment3.mRemoving = true;
                o0Var2.i();
            }
        }
        ArrayList<String> arrayList = fragmentManagerState.b;
        q0Var.a.clear();
        if (arrayList != null) {
            for (String str3 : arrayList) {
                Fragment fragmentB = q0Var.b(str3);
                if (fragmentB == null) {
                    throw new IllegalStateException(android.support.v4.media.session.a.B("No instantiated fragment for (", str3, ")"));
                }
                if (N(2)) {
                    fragmentB.toString();
                }
                q0Var.a(fragmentB);
            }
        }
        if (fragmentManagerState.c != null) {
            this.d = new ArrayList(fragmentManagerState.c.length);
            int i = 0;
            while (true) {
                BackStackRecordState[] backStackRecordStateArr = fragmentManagerState.c;
                if (i >= backStackRecordStateArr.length) {
                    break;
                }
                BackStackRecordState backStackRecordState = backStackRecordStateArr[i];
                backStackRecordState.getClass();
                C1121a c1121a = new C1121a(this);
                int i2 = 0;
                int i3 = 0;
                while (true) {
                    int[] iArr = backStackRecordState.a;
                    if (i2 >= iArr.length) {
                        break;
                    }
                    r0 r0Var = new r0();
                    int i4 = i2 + 1;
                    r0Var.a = iArr[i2];
                    if (N(2)) {
                        Objects.toString(c1121a);
                        int i5 = iArr[i4];
                    }
                    r0Var.h = androidx.lifecycle.B.values()[backStackRecordState.c[i3]];
                    r0Var.i = androidx.lifecycle.B.values()[backStackRecordState.d[i3]];
                    int i6 = i2 + 2;
                    r0Var.c = iArr[i4] != 0;
                    int i7 = iArr[i6];
                    r0Var.d = i7;
                    int i8 = iArr[i2 + 3];
                    r0Var.e = i8;
                    int i9 = i2 + 5;
                    int i10 = iArr[i2 + 4];
                    r0Var.f = i10;
                    i2 += 6;
                    int i11 = iArr[i9];
                    r0Var.g = i11;
                    c1121a.b = i7;
                    c1121a.c = i8;
                    c1121a.d = i10;
                    c1121a.e = i11;
                    c1121a.c(r0Var);
                    i3++;
                }
                c1121a.f = backStackRecordState.e;
                c1121a.i = backStackRecordState.f;
                c1121a.g = true;
                c1121a.j = backStackRecordState.h;
                c1121a.k = backStackRecordState.i;
                c1121a.l = backStackRecordState.j;
                c1121a.m = backStackRecordState.k;
                c1121a.n = backStackRecordState.l;
                c1121a.o = backStackRecordState.m;
                c1121a.p = backStackRecordState.n;
                c1121a.t = backStackRecordState.g;
                int i12 = 0;
                while (true) {
                    ArrayList arrayList2 = backStackRecordState.b;
                    if (i12 >= arrayList2.size()) {
                        break;
                    }
                    String str4 = (String) arrayList2.get(i12);
                    if (str4 != null) {
                        ((r0) c1121a.a.get(i12)).b = q0Var.b(str4);
                    }
                    i12++;
                }
                c1121a.e(1);
                if (N(2)) {
                    c1121a.toString();
                    PrintWriter printWriter = new PrintWriter(new E0());
                    c1121a.j("  ", printWriter, false);
                    printWriter.close();
                }
                this.d.add(c1121a);
                i++;
            }
        } else {
            this.d = new ArrayList();
        }
        this.k.set(fragmentManagerState.d);
        String str5 = fragmentManagerState.e;
        if (str5 != null) {
            Fragment fragmentB2 = q0Var.b(str5);
            this.A = fragmentB2;
            s(fragmentB2);
        }
        ArrayList arrayList3 = fragmentManagerState.f;
        if (arrayList3 != null) {
            for (int i13 = 0; i13 < arrayList3.size(); i13++) {
                this.l.put((String) arrayList3.get(i13), (BackStackState) fragmentManagerState.g.get(i13));
            }
        }
        this.G = new ArrayDeque(fragmentManagerState.h);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void c(O o, L l, Fragment fragment) {
        if (this.x != null) {
            throw new IllegalStateException("Already attached");
        }
        this.x = o;
        this.y = l;
        this.z = fragment;
        if (fragment != null) {
            b(new C1122a0(fragment));
        } else if (o instanceof InterfaceC1144l0) {
            b((InterfaceC1144l0) o);
        }
        if (this.z != null) {
            m0();
        }
        if (o instanceof androidx.activity.N) {
            androidx.activity.N n = (androidx.activity.N) o;
            androidx.activity.L onBackPressedDispatcher = n.getOnBackPressedDispatcher();
            this.g = onBackPressedDispatcher;
            androidx.lifecycle.J j = n;
            if (fragment != null) {
                j = fragment;
            }
            onBackPressedDispatcher.a(j, this.j);
        }
        if (fragment != null) {
            C1142k0 c1142k0 = fragment.mFragmentManager.P;
            HashMap map = c1142k0.c;
            C1142k0 c1142k02 = (C1142k0) map.get(fragment.mWho);
            if (c1142k02 == null) {
                c1142k02 = new C1142k0(c1142k0.e);
                map.put(fragment.mWho, c1142k02);
            }
            this.P = c1142k02;
        } else if (o instanceof androidx.lifecycle.C0) {
            androidx.lifecycle.B0 store = ((androidx.lifecycle.C0) o).getViewModelStore();
            C1140j0 factory = C1142k0.h;
            Intrinsics.checkNotNullParameter(store, "store");
            Intrinsics.checkNotNullParameter(factory, "factory");
            androidx.lifecycle.viewmodel.a defaultCreationExtras = androidx.lifecycle.viewmodel.a.b;
            Intrinsics.checkNotNullParameter(store, "store");
            Intrinsics.checkNotNullParameter(factory, "factory");
            Intrinsics.checkNotNullParameter(defaultCreationExtras, "defaultCreationExtras");
            com.quizlet.data.repository.metering.j jVar = new com.quizlet.data.repository.metering.j(store, factory, defaultCreationExtras);
            Intrinsics.checkNotNullParameter(C1142k0.class, "modelClass");
            Intrinsics.checkNotNullParameter(C1142k0.class, "<this>");
            C4950i modelClass = kotlin.jvm.internal.K.a(C1142k0.class);
            Intrinsics.checkNotNullParameter(modelClass, "modelClass");
            Intrinsics.checkNotNullParameter(modelClass, "modelClass");
            String strB = C1.b(modelClass);
            if (strB == null) {
                throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
            }
            this.P = (C1142k0) jVar.e(modelClass, "androidx.lifecycle.ViewModelProvider.DefaultKey:".concat(strB));
        } else {
            this.P = new C1142k0(false);
        }
        this.P.g = R();
        this.c.d = this.P;
        Object obj = this.x;
        if ((obj instanceof androidx.savedstate.f) && fragment == null) {
            androidx.savedstate.d savedStateRegistry = ((androidx.savedstate.f) obj).getSavedStateRegistry();
            savedStateRegistry.c("android:support:fragments", new E(this, 1));
            Bundle bundleA = savedStateRegistry.a("android:support:fragments");
            if (bundleA != null) {
                b0(bundleA);
            }
        }
        Object obj2 = this.x;
        if (obj2 instanceof androidx.activity.result.i) {
            androidx.activity.result.h activityResultRegistry = ((androidx.activity.result.i) obj2).getActivityResultRegistry();
            String strD = AbstractC0147y.d("FragmentManager:", fragment != null ? android.support.v4.media.session.a.t(new StringBuilder(), fragment.mWho, ":") : "");
            this.D = activityResultRegistry.c(android.support.v4.media.session.a.k(strD, "StartActivityForResult"), new androidx.activity.result.contract.b(4), new U(1, this));
            this.E = activityResultRegistry.c(android.support.v4.media.session.a.k(strD, "StartIntentSenderForResult"), new androidx.activity.result.contract.b(6), new U(2, this));
            this.F = activityResultRegistry.c(android.support.v4.media.session.a.k(strD, "RequestPermissions"), new androidx.activity.result.contract.b(2), new U(0, this));
        }
        Object obj3 = this.x;
        if (obj3 instanceof androidx.core.content.f) {
            ((androidx.core.content.f) obj3).addOnConfigurationChangedListener(this.r);
        }
        Object obj4 = this.x;
        if (obj4 instanceof androidx.core.content.g) {
            ((androidx.core.content.g) obj4).addOnTrimMemoryListener(this.s);
        }
        Object obj5 = this.x;
        if (obj5 instanceof androidx.core.app.O) {
            ((androidx.core.app.O) obj5).addOnMultiWindowModeChangedListener(this.t);
        }
        Object obj6 = this.x;
        if (obj6 instanceof androidx.core.app.P) {
            ((androidx.core.app.P) obj6).addOnPictureInPictureModeChangedListener(this.u);
        }
        Object obj7 = this.x;
        if ((obj7 instanceof InterfaceC1056m) && fragment == null) {
            ((InterfaceC1056m) obj7).addMenuProvider(this.v);
        }
    }

    public final Bundle c0() {
        ArrayList arrayList;
        BackStackRecordState[] backStackRecordStateArr;
        Bundle bundle = new Bundle();
        H();
        x();
        A(true);
        this.I = true;
        this.P.g = true;
        q0 q0Var = this.c;
        q0Var.getClass();
        HashMap map = q0Var.b;
        ArrayList arrayList2 = new ArrayList(map.size());
        for (o0 o0Var : map.values()) {
            if (o0Var != null) {
                Fragment fragment = o0Var.c;
                q0Var.i(o0Var.l(), fragment.mWho);
                arrayList2.add(fragment.mWho);
                if (N(2)) {
                    fragment.toString();
                    Objects.toString(fragment.mSavedFragmentState);
                }
            }
        }
        HashMap map2 = this.c.c;
        if (map2.isEmpty()) {
            N(2);
            return bundle;
        }
        q0 q0Var2 = this.c;
        synchronized (q0Var2.a) {
            try {
                if (q0Var2.a.isEmpty()) {
                    arrayList = null;
                } else {
                    arrayList = new ArrayList(q0Var2.a.size());
                    Iterator it2 = q0Var2.a.iterator();
                    while (it2.hasNext()) {
                        Fragment fragment2 = (Fragment) it2.next();
                        arrayList.add(fragment2.mWho);
                        if (N(2)) {
                            fragment2.toString();
                        }
                    }
                }
            } finally {
            }
        }
        int size = this.d.size();
        if (size > 0) {
            backStackRecordStateArr = new BackStackRecordState[size];
            for (int i = 0; i < size; i++) {
                backStackRecordStateArr[i] = new BackStackRecordState((C1121a) this.d.get(i));
                if (N(2)) {
                    Objects.toString(this.d.get(i));
                }
            }
        } else {
            backStackRecordStateArr = null;
        }
        FragmentManagerState fragmentManagerState = new FragmentManagerState();
        fragmentManagerState.e = null;
        ArrayList arrayList3 = new ArrayList();
        fragmentManagerState.f = arrayList3;
        ArrayList arrayList4 = new ArrayList();
        fragmentManagerState.g = arrayList4;
        fragmentManagerState.a = arrayList2;
        fragmentManagerState.b = arrayList;
        fragmentManagerState.c = backStackRecordStateArr;
        fragmentManagerState.d = this.k.get();
        Fragment fragment3 = this.A;
        if (fragment3 != null) {
            fragmentManagerState.e = fragment3.mWho;
        }
        arrayList3.addAll(this.l.keySet());
        arrayList4.addAll(this.l.values());
        fragmentManagerState.h = new ArrayList(this.G);
        bundle.putParcelable("state", fragmentManagerState);
        for (String str : this.m.keySet()) {
            bundle.putBundle(AbstractC0147y.d("result_", str), (Bundle) this.m.get(str));
        }
        for (String str2 : map2.keySet()) {
            bundle.putBundle(AbstractC0147y.d("fragment_", str2), (Bundle) map2.get(str2));
        }
        return bundle;
    }

    public final void d(Fragment fragment) {
        if (N(2)) {
            Objects.toString(fragment);
        }
        if (fragment.mDetached) {
            fragment.mDetached = false;
            if (fragment.mAdded) {
                return;
            }
            this.c.a(fragment);
            if (N(2)) {
                fragment.toString();
            }
            if (O(fragment)) {
                this.H = true;
            }
        }
    }

    public final Fragment.SavedState d0(Fragment fragment) {
        o0 o0Var = (o0) this.c.b.get(fragment.mWho);
        if (o0Var != null) {
            Fragment fragment2 = o0Var.c;
            if (fragment2.equals(fragment)) {
                if (fragment2.mState > -1) {
                    return new Fragment.SavedState(o0Var.l());
                }
                return null;
            }
        }
        l0(new IllegalStateException(androidx.compose.ui.node.B.g("Fragment ", fragment, " is not currently in the FragmentManager")));
        throw null;
    }

    public final void e() {
        this.b = false;
        this.N.clear();
        this.M.clear();
    }

    public final void e0() {
        synchronized (this.a) {
            try {
                if (this.a.size() == 1) {
                    this.x.c.removeCallbacks(this.Q);
                    this.x.c.post(this.Q);
                    m0();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final HashSet f() {
        C1147o c1147o;
        HashSet hashSet = new HashSet();
        Iterator it2 = this.c.d().iterator();
        while (it2.hasNext()) {
            ViewGroup container = ((o0) it2.next()).c.mContainer;
            if (container != null) {
                Y factory = M();
                Intrinsics.checkNotNullParameter(container, "container");
                Intrinsics.checkNotNullParameter(factory, "factory");
                Object tag = container.getTag(R.id.special_effects_controller_view_tag);
                if (tag instanceof C1147o) {
                    c1147o = (C1147o) tag;
                } else {
                    factory.getClass();
                    Intrinsics.checkNotNullParameter(container, "container");
                    c1147o = new C1147o(container);
                    Intrinsics.checkNotNullExpressionValue(c1147o, "factory.createController(container)");
                    container.setTag(R.id.special_effects_controller_view_tag, c1147o);
                }
                hashSet.add(c1147o);
            }
        }
        return hashSet;
    }

    public final void f0(Fragment fragment, boolean z) {
        ViewGroup viewGroupK = K(fragment);
        if (viewGroupK == null || !(viewGroupK instanceof FragmentContainerView)) {
            return;
        }
        ((FragmentContainerView) viewGroupK).setDrawDisappearingViewsLast(!z);
    }

    public final HashSet g(ArrayList arrayList, int i, int i2) {
        ViewGroup viewGroup;
        HashSet hashSet = new HashSet();
        while (i < i2) {
            Iterator it2 = ((C1121a) arrayList.get(i)).a.iterator();
            while (it2.hasNext()) {
                Fragment fragment = ((r0) it2.next()).b;
                if (fragment != null && (viewGroup = fragment.mContainer) != null) {
                    hashSet.add(C1147o.j(viewGroup, this));
                }
            }
            i++;
        }
        return hashSet;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x001c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void g0(android.os.Bundle r4, java.lang.String r5) {
        /*
            r3 = this;
            java.util.Map r0 = r3.n
            java.lang.Object r0 = r0.get(r5)
            androidx.fragment.app.c0 r0 = (androidx.fragment.app.C1126c0) r0
            if (r0 == 0) goto L1c
            androidx.lifecycle.B r1 = androidx.lifecycle.B.d
            androidx.lifecycle.C r2 = r0.a
            androidx.lifecycle.L r2 = (androidx.lifecycle.L) r2
            androidx.lifecycle.B r2 = r2.d
            boolean r1 = r2.a(r1)
            if (r1 == 0) goto L1c
            r0.y(r4, r5)
            goto L21
        L1c:
            java.util.Map r0 = r3.m
            r0.put(r5, r4)
        L21:
            r5 = 2
            boolean r5 = N(r5)
            if (r5 == 0) goto L2b
            java.util.Objects.toString(r4)
        L2b:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.fragment.app.AbstractC1136h0.g0(android.os.Bundle, java.lang.String):void");
    }

    public final o0 h(Fragment fragment) {
        String str = fragment.mWho;
        q0 q0Var = this.c;
        o0 o0Var = (o0) q0Var.b.get(str);
        if (o0Var != null) {
            return o0Var;
        }
        o0 o0Var2 = new o0(this.p, q0Var, fragment);
        o0Var2.j(this.x.b.getClassLoader());
        o0Var2.e = this.w;
        return o0Var2;
    }

    public final void h0(String str, androidx.lifecycle.J j, m0 m0Var) {
        androidx.lifecycle.C lifecycle = j.getLifecycle();
        if (((androidx.lifecycle.L) lifecycle).d == androidx.lifecycle.B.a) {
            return;
        }
        Z z = new Z(this, str, m0Var, lifecycle);
        C1126c0 c1126c0 = (C1126c0) this.n.put(str, new C1126c0(lifecycle, m0Var, z));
        if (c1126c0 != null) {
            c1126c0.a.b(c1126c0.c);
        }
        if (N(2)) {
            lifecycle.toString();
            Objects.toString(m0Var);
        }
        lifecycle.a(z);
    }

    public final void i(Fragment fragment) {
        if (N(2)) {
            Objects.toString(fragment);
        }
        if (fragment.mDetached) {
            return;
        }
        fragment.mDetached = true;
        if (fragment.mAdded) {
            if (N(2)) {
                fragment.toString();
            }
            q0 q0Var = this.c;
            synchronized (q0Var.a) {
                q0Var.a.remove(fragment);
            }
            fragment.mAdded = false;
            if (O(fragment)) {
                this.H = true;
            }
            k0(fragment);
        }
    }

    public final void i0(Fragment fragment, androidx.lifecycle.B b) {
        if (fragment.equals(this.c.b(fragment.mWho)) && (fragment.mHost == null || fragment.mFragmentManager == this)) {
            fragment.mMaxState = b;
            return;
        }
        throw new IllegalArgumentException("Fragment " + fragment + " is not an active fragment of FragmentManager " + this);
    }

    public final void j(boolean z, Configuration configuration) {
        if (z && (this.x instanceof androidx.core.content.f)) {
            l0(new IllegalStateException("Do not call dispatchConfigurationChanged() on host. Host implements OnConfigurationChangedProvider and automatically dispatches configuration changes to fragments."));
            throw null;
        }
        for (Fragment fragment : this.c.f()) {
            if (fragment != null) {
                fragment.performConfigurationChanged(configuration);
                if (z) {
                    fragment.mChildFragmentManager.j(true, configuration);
                }
            }
        }
    }

    public final void j0(Fragment fragment) {
        if (fragment != null) {
            if (!fragment.equals(this.c.b(fragment.mWho)) || (fragment.mHost != null && fragment.mFragmentManager != this)) {
                throw new IllegalArgumentException("Fragment " + fragment + " is not an active fragment of FragmentManager " + this);
            }
        }
        Fragment fragment2 = this.A;
        this.A = fragment;
        s(fragment2);
        s(this.A);
    }

    public final boolean k(MenuItem menuItem) {
        if (this.w < 1) {
            return false;
        }
        for (Fragment fragment : this.c.f()) {
            if (fragment != null && fragment.performContextItemSelected(menuItem)) {
                return true;
            }
        }
        return false;
    }

    public final void k0(Fragment fragment) {
        ViewGroup viewGroupK = K(fragment);
        if (viewGroupK != null) {
            if (fragment.getPopExitAnim() + fragment.getPopEnterAnim() + fragment.getExitAnim() + fragment.getEnterAnim() > 0) {
                if (viewGroupK.getTag(R.id.visible_removing_fragment_view_tag) == null) {
                    viewGroupK.setTag(R.id.visible_removing_fragment_view_tag, fragment);
                }
                ((Fragment) viewGroupK.getTag(R.id.visible_removing_fragment_view_tag)).setPopDirection(fragment.getPopDirection());
            }
        }
    }

    public final boolean l(Menu menu, MenuInflater menuInflater) {
        if (this.w < 1) {
            return false;
        }
        ArrayList arrayList = null;
        boolean z = false;
        for (Fragment fragment : this.c.f()) {
            if (fragment != null && fragment.isMenuVisible() && fragment.performCreateOptionsMenu(menu, menuInflater)) {
                if (arrayList == null) {
                    arrayList = new ArrayList();
                }
                arrayList.add(fragment);
                z = true;
            }
        }
        if (this.e != null) {
            for (int i = 0; i < this.e.size(); i++) {
                Fragment fragment2 = (Fragment) this.e.get(i);
                if (arrayList == null || !arrayList.contains(fragment2)) {
                    fragment2.onDestroyOptionsMenu();
                }
            }
        }
        this.e = arrayList;
        return z;
    }

    public final void l0(IllegalStateException illegalStateException) {
        Log.e("FragmentManager", illegalStateException.getMessage());
        Log.e("FragmentManager", "Activity state:");
        PrintWriter printWriter = new PrintWriter(new E0());
        O o = this.x;
        if (o == null) {
            try {
                w("  ", null, printWriter, new String[0]);
                throw illegalStateException;
            } catch (Exception e) {
                Log.e("FragmentManager", "Failed dumping state", e);
                throw illegalStateException;
            }
        }
        try {
            ((H) o).e.dump("  ", null, printWriter, new String[0]);
            throw illegalStateException;
        } catch (Exception e2) {
            Log.e("FragmentManager", "Failed dumping state", e2);
            throw illegalStateException;
        }
    }

    public final void m() {
        boolean zIsChangingConfigurations = true;
        this.K = true;
        A(true);
        x();
        O o = this.x;
        boolean z = o instanceof androidx.lifecycle.C0;
        q0 q0Var = this.c;
        if (z) {
            zIsChangingConfigurations = q0Var.d.f;
        } else {
            I i = o.b;
            if (i != null) {
                zIsChangingConfigurations = true ^ i.isChangingConfigurations();
            }
        }
        if (zIsChangingConfigurations) {
            Iterator it2 = this.l.values().iterator();
            while (it2.hasNext()) {
                for (String str : ((BackStackState) it2.next()).a) {
                    C1142k0 c1142k0 = q0Var.d;
                    c1142k0.getClass();
                    N(3);
                    c1142k0.B(str, false);
                }
            }
        }
        v(-1);
        Object obj = this.x;
        if (obj instanceof androidx.core.content.g) {
            ((androidx.core.content.g) obj).removeOnTrimMemoryListener(this.s);
        }
        Object obj2 = this.x;
        if (obj2 instanceof androidx.core.content.f) {
            ((androidx.core.content.f) obj2).removeOnConfigurationChangedListener(this.r);
        }
        Object obj3 = this.x;
        if (obj3 instanceof androidx.core.app.O) {
            ((androidx.core.app.O) obj3).removeOnMultiWindowModeChangedListener(this.t);
        }
        Object obj4 = this.x;
        if (obj4 instanceof androidx.core.app.P) {
            ((androidx.core.app.P) obj4).removeOnPictureInPictureModeChangedListener(this.u);
        }
        Object obj5 = this.x;
        if ((obj5 instanceof InterfaceC1056m) && this.z == null) {
            ((InterfaceC1056m) obj5).removeMenuProvider(this.v);
        }
        this.x = null;
        this.y = null;
        this.z = null;
        if (this.g != null) {
            this.j.e();
            this.g = null;
        }
        androidx.activity.result.g gVar = this.D;
        if (gVar != null) {
            gVar.b();
            this.E.b();
            this.F.b();
        }
    }

    /* JADX WARN: Type inference failed for: r0v4, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.o] */
    /* JADX WARN: Type inference failed for: r1v4, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.o] */
    public final void m0() {
        synchronized (this.a) {
            try {
                if (!this.a.isEmpty()) {
                    V v = this.j;
                    v.a = true;
                    ?? r1 = v.c;
                    if (r1 != 0) {
                        r1.invoke();
                    }
                    if (N(3)) {
                        toString();
                    }
                    return;
                }
                boolean z = J() > 0 && Q(this.z);
                if (N(3)) {
                    toString();
                }
                V v2 = this.j;
                v2.a = z;
                ?? r0 = v2.c;
                if (r0 != 0) {
                    r0.invoke();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void n(boolean z) {
        if (z && (this.x instanceof androidx.core.content.g)) {
            l0(new IllegalStateException("Do not call dispatchLowMemory() on host. Host implements OnTrimMemoryProvider and automatically dispatches low memory callbacks to fragments."));
            throw null;
        }
        for (Fragment fragment : this.c.f()) {
            if (fragment != null) {
                fragment.performLowMemory();
                if (z) {
                    fragment.mChildFragmentManager.n(true);
                }
            }
        }
    }

    public final void o(boolean z, boolean z2) {
        if (z2 && (this.x instanceof androidx.core.app.O)) {
            l0(new IllegalStateException("Do not call dispatchMultiWindowModeChanged() on host. Host implements OnMultiWindowModeChangedProvider and automatically dispatches multi-window mode changes to fragments."));
            throw null;
        }
        for (Fragment fragment : this.c.f()) {
            if (fragment != null) {
                fragment.performMultiWindowModeChanged(z);
                if (z2) {
                    fragment.mChildFragmentManager.o(z, true);
                }
            }
        }
    }

    public final void p() {
        Iterator it2 = this.c.e().iterator();
        while (it2.hasNext()) {
            Fragment fragment = (Fragment) it2.next();
            if (fragment != null) {
                fragment.onHiddenChanged(fragment.isHidden());
                fragment.mChildFragmentManager.p();
            }
        }
    }

    public final boolean q(MenuItem menuItem) {
        if (this.w < 1) {
            return false;
        }
        for (Fragment fragment : this.c.f()) {
            if (fragment != null && fragment.performOptionsItemSelected(menuItem)) {
                return true;
            }
        }
        return false;
    }

    public final void r(Menu menu) {
        if (this.w < 1) {
            return;
        }
        for (Fragment fragment : this.c.f()) {
            if (fragment != null) {
                fragment.performOptionsMenuClosed(menu);
            }
        }
    }

    public final void s(Fragment fragment) {
        if (fragment != null) {
            if (fragment.equals(this.c.b(fragment.mWho))) {
                fragment.performPrimaryNavigationFragmentChanged();
            }
        }
    }

    public final void t(boolean z, boolean z2) {
        if (z2 && (this.x instanceof androidx.core.app.P)) {
            l0(new IllegalStateException("Do not call dispatchPictureInPictureModeChanged() on host. Host implements OnPictureInPictureModeChangedProvider and automatically dispatches picture-in-picture mode changes to fragments."));
            throw null;
        }
        for (Fragment fragment : this.c.f()) {
            if (fragment != null) {
                fragment.performPictureInPictureModeChanged(z);
                if (z2) {
                    fragment.mChildFragmentManager.t(z, true);
                }
            }
        }
    }

    public final String toString() {
        StringBuilder sbL = androidx.compose.ui.node.B.l(128, "FragmentManager{");
        sbL.append(Integer.toHexString(System.identityHashCode(this)));
        sbL.append(" in ");
        Fragment fragment = this.z;
        if (fragment != null) {
            sbL.append(fragment.getClass().getSimpleName());
            sbL.append("{");
            sbL.append(Integer.toHexString(System.identityHashCode(this.z)));
            sbL.append("}");
        } else {
            O o = this.x;
            if (o != null) {
                sbL.append(o.getClass().getSimpleName());
                sbL.append("{");
                sbL.append(Integer.toHexString(System.identityHashCode(this.x)));
                sbL.append("}");
            } else {
                sbL.append("null");
            }
        }
        sbL.append("}}");
        return sbL.toString();
    }

    public final boolean u(Menu menu) {
        boolean z = false;
        if (this.w < 1) {
            return false;
        }
        for (Fragment fragment : this.c.f()) {
            if (fragment != null && fragment.isMenuVisible() && fragment.performPrepareOptionsMenu(menu)) {
                z = true;
            }
        }
        return z;
    }

    public final void v(int i) {
        try {
            this.b = true;
            for (o0 o0Var : this.c.b.values()) {
                if (o0Var != null) {
                    o0Var.e = i;
                }
            }
            S(i, false);
            Iterator it2 = f().iterator();
            while (it2.hasNext()) {
                ((C1147o) it2.next()).i();
            }
            this.b = false;
            A(true);
        } catch (Throwable th) {
            this.b = false;
            throw th;
        }
    }

    public final void w(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        int size;
        String strK = android.support.v4.media.session.a.k(str, "    ");
        q0 q0Var = this.c;
        q0Var.getClass();
        String str2 = str + "    ";
        HashMap map = q0Var.b;
        if (!map.isEmpty()) {
            printWriter.print(str);
            printWriter.println("Active Fragments:");
            for (o0 o0Var : map.values()) {
                printWriter.print(str);
                if (o0Var != null) {
                    Fragment fragment = o0Var.c;
                    printWriter.println(fragment);
                    fragment.dump(str2, fileDescriptor, printWriter, strArr);
                } else {
                    printWriter.println("null");
                }
            }
        }
        ArrayList arrayList = q0Var.a;
        int size2 = arrayList.size();
        if (size2 > 0) {
            printWriter.print(str);
            printWriter.println("Added Fragments:");
            for (int i = 0; i < size2; i++) {
                Fragment fragment2 = (Fragment) arrayList.get(i);
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(i);
                printWriter.print(": ");
                printWriter.println(fragment2.toString());
            }
        }
        ArrayList arrayList2 = this.e;
        if (arrayList2 != null && (size = arrayList2.size()) > 0) {
            printWriter.print(str);
            printWriter.println("Fragments Created Menus:");
            for (int i2 = 0; i2 < size; i2++) {
                Fragment fragment3 = (Fragment) this.e.get(i2);
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(i2);
                printWriter.print(": ");
                printWriter.println(fragment3.toString());
            }
        }
        int size3 = this.d.size();
        if (size3 > 0) {
            printWriter.print(str);
            printWriter.println("Back Stack:");
            for (int i3 = 0; i3 < size3; i3++) {
                C1121a c1121a = (C1121a) this.d.get(i3);
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(i3);
                printWriter.print(": ");
                printWriter.println(c1121a.toString());
                c1121a.j(strK, printWriter, true);
            }
        }
        printWriter.print(str);
        printWriter.println("Back Stack Index: " + this.k.get());
        synchronized (this.a) {
            try {
                int size4 = this.a.size();
                if (size4 > 0) {
                    printWriter.print(str);
                    printWriter.println("Pending Actions:");
                    for (int i4 = 0; i4 < size4; i4++) {
                        Object obj = (InterfaceC1130e0) this.a.get(i4);
                        printWriter.print(str);
                        printWriter.print("  #");
                        printWriter.print(i4);
                        printWriter.print(": ");
                        printWriter.println(obj);
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        printWriter.print(str);
        printWriter.println("FragmentManager misc state:");
        printWriter.print(str);
        printWriter.print("  mHost=");
        printWriter.println(this.x);
        printWriter.print(str);
        printWriter.print("  mContainer=");
        printWriter.println(this.y);
        if (this.z != null) {
            printWriter.print(str);
            printWriter.print("  mParent=");
            printWriter.println(this.z);
        }
        printWriter.print(str);
        printWriter.print("  mCurState=");
        printWriter.print(this.w);
        printWriter.print(" mStateSaved=");
        printWriter.print(this.I);
        printWriter.print(" mStopped=");
        printWriter.print(this.J);
        printWriter.print(" mDestroyed=");
        printWriter.println(this.K);
        if (this.H) {
            printWriter.print(str);
            printWriter.print("  mNeedMenuInvalidate=");
            printWriter.println(this.H);
        }
    }

    public final void x() {
        Iterator it2 = f().iterator();
        while (it2.hasNext()) {
            ((C1147o) it2.next()).i();
        }
    }

    public final void y(InterfaceC1130e0 interfaceC1130e0, boolean z) {
        if (!z) {
            if (this.x == null) {
                if (!this.K) {
                    throw new IllegalStateException("FragmentManager has not been attached to a host.");
                }
                throw new IllegalStateException("FragmentManager has been destroyed");
            }
            if (R()) {
                throw new IllegalStateException("Can not perform this action after onSaveInstanceState");
            }
        }
        synchronized (this.a) {
            try {
                if (this.x == null) {
                    if (!z) {
                        throw new IllegalStateException("Activity has been destroyed");
                    }
                } else {
                    this.a.add(interfaceC1130e0);
                    e0();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void z(boolean z) {
        if (this.b) {
            throw new IllegalStateException("FragmentManager is already executing transactions");
        }
        if (this.x == null) {
            if (!this.K) {
                throw new IllegalStateException("FragmentManager has not been attached to a host.");
            }
            throw new IllegalStateException("FragmentManager has been destroyed");
        }
        if (Looper.myLooper() != this.x.c.getLooper()) {
            throw new IllegalStateException("Must be called from main thread of fragment host");
        }
        if (!z && R()) {
            throw new IllegalStateException("Can not perform this action after onSaveInstanceState");
        }
        if (this.M == null) {
            this.M = new ArrayList();
            this.N = new ArrayList();
        }
    }
}
