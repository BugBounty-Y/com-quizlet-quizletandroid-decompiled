package androidx.fragment.app;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.quizlet.quizletandroid.R;
import java.io.PrintWriter;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Objects;

/* renamed from: androidx.fragment.app.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1121a implements InterfaceC1130e0 {
    public final ArrayList a;
    public int b;
    public int c;
    public int d;
    public int e;
    public int f;
    public boolean g;
    public boolean h;
    public String i;
    public int j;
    public CharSequence k;
    public int l;
    public CharSequence m;
    public ArrayList n;
    public ArrayList o;
    public boolean p;
    public ArrayList q;
    public final AbstractC1136h0 r;
    public boolean s;
    public int t;

    public C1121a(AbstractC1136h0 abstractC1136h0) {
        abstractC1136h0.L();
        O o = abstractC1136h0.x;
        if (o != null) {
            o.b.getClassLoader();
        }
        this.a = new ArrayList();
        this.h = true;
        this.p = false;
        this.t = -1;
        this.r = abstractC1136h0;
    }

    @Override // androidx.fragment.app.InterfaceC1130e0
    public final boolean a(ArrayList arrayList, ArrayList arrayList2) {
        if (AbstractC1136h0.N(2)) {
            toString();
        }
        arrayList.add(this);
        arrayList2.add(Boolean.FALSE);
        if (!this.g) {
            return true;
        }
        this.r.d.add(this);
        return true;
    }

    public final void b(FragmentContainerView fragmentContainerView, Fragment fragment, String str) {
        fragment.mContainer = fragmentContainerView;
        fragment.mInDynamicContainer = true;
        i(fragmentContainerView.getId(), fragment, str, 1);
    }

    public final void c(r0 r0Var) {
        this.a.add(r0Var);
        r0Var.d = this.b;
        r0Var.e = this.c;
        r0Var.f = this.d;
        r0Var.g = this.e;
    }

    public final void d(String str) {
        if (!this.h) {
            throw new IllegalStateException("This FragmentTransaction is not allowed to be added to the back stack.");
        }
        this.g = true;
        this.i = str;
    }

    public final void e(int i) {
        if (this.g) {
            if (AbstractC1136h0.N(2)) {
                toString();
            }
            ArrayList arrayList = this.a;
            int size = arrayList.size();
            for (int i2 = 0; i2 < size; i2++) {
                r0 r0Var = (r0) arrayList.get(i2);
                Fragment fragment = r0Var.b;
                if (fragment != null) {
                    fragment.mBackStackNesting += i;
                    if (AbstractC1136h0.N(2)) {
                        Objects.toString(r0Var.b);
                        int i3 = r0Var.b.mBackStackNesting;
                    }
                }
            }
        }
    }

    public final void f() {
        ArrayList arrayList = this.a;
        int size = arrayList.size() - 1;
        while (size >= 0) {
            r0 r0Var = (r0) arrayList.get(size);
            if (r0Var.c) {
                if (r0Var.a == 8) {
                    r0Var.c = false;
                    arrayList.remove(size - 1);
                    size--;
                } else {
                    int i = r0Var.b.mContainerId;
                    r0Var.a = 2;
                    r0Var.c = false;
                    for (int i2 = size - 1; i2 >= 0; i2--) {
                        r0 r0Var2 = (r0) arrayList.get(i2);
                        if (r0Var2.c && r0Var2.b.mContainerId == i) {
                            arrayList.remove(i2);
                            size--;
                        }
                    }
                }
            }
            size--;
        }
    }

    public final void g() {
        h(false, true);
    }

    public final int h(boolean z, boolean z2) {
        if (this.s) {
            throw new IllegalStateException("commit already called");
        }
        if (AbstractC1136h0.N(2)) {
            toString();
            PrintWriter printWriter = new PrintWriter(new E0());
            j("  ", printWriter, true);
            printWriter.close();
        }
        this.s = true;
        boolean z3 = this.g;
        AbstractC1136h0 abstractC1136h0 = this.r;
        if (z3) {
            this.t = abstractC1136h0.k.getAndIncrement();
        } else {
            this.t = -1;
        }
        if (z2) {
            abstractC1136h0.y(this, z);
        }
        return this.t;
    }

    public final void i(int i, Fragment fragment, String str, int i2) {
        String str2 = fragment.mPreviousWho;
        if (str2 != null) {
            androidx.fragment.app.strictmode.c.c(fragment, str2);
        }
        Class<?> cls = fragment.getClass();
        int modifiers = cls.getModifiers();
        if (cls.isAnonymousClass() || !Modifier.isPublic(modifiers) || (cls.isMemberClass() && !Modifier.isStatic(modifiers))) {
            throw new IllegalStateException("Fragment " + cls.getCanonicalName() + " must be a public static class to be  properly recreated from instance state.");
        }
        if (str != null) {
            String str3 = fragment.mTag;
            if (str3 != null && !str.equals(str3)) {
                StringBuilder sb = new StringBuilder("Can't change tag of fragment ");
                sb.append(fragment);
                sb.append(": was ");
                throw new IllegalStateException(AbstractC0147y.g(sb, fragment.mTag, " now ", str));
            }
            fragment.mTag = str;
        }
        if (i != 0) {
            if (i == -1) {
                throw new IllegalArgumentException("Can't add fragment " + fragment + " with tag " + str + " to container view with no id");
            }
            int i3 = fragment.mFragmentId;
            if (i3 != 0 && i3 != i) {
                throw new IllegalStateException("Can't change container ID of fragment " + fragment + ": was " + fragment.mFragmentId + " now " + i);
            }
            fragment.mFragmentId = i;
            fragment.mContainerId = i;
        }
        c(new r0(fragment, i2));
        fragment.mFragmentManager = this.r;
    }

    public final void j(String str, PrintWriter printWriter, boolean z) {
        String str2;
        if (z) {
            printWriter.print(str);
            printWriter.print("mName=");
            printWriter.print(this.i);
            printWriter.print(" mIndex=");
            printWriter.print(this.t);
            printWriter.print(" mCommitted=");
            printWriter.println(this.s);
            if (this.f != 0) {
                printWriter.print(str);
                printWriter.print("mTransition=#");
                printWriter.print(Integer.toHexString(this.f));
            }
            if (this.b != 0 || this.c != 0) {
                printWriter.print(str);
                printWriter.print("mEnterAnim=#");
                printWriter.print(Integer.toHexString(this.b));
                printWriter.print(" mExitAnim=#");
                printWriter.println(Integer.toHexString(this.c));
            }
            if (this.d != 0 || this.e != 0) {
                printWriter.print(str);
                printWriter.print("mPopEnterAnim=#");
                printWriter.print(Integer.toHexString(this.d));
                printWriter.print(" mPopExitAnim=#");
                printWriter.println(Integer.toHexString(this.e));
            }
            if (this.j != 0 || this.k != null) {
                printWriter.print(str);
                printWriter.print("mBreadCrumbTitleRes=#");
                printWriter.print(Integer.toHexString(this.j));
                printWriter.print(" mBreadCrumbTitleText=");
                printWriter.println(this.k);
            }
            if (this.l != 0 || this.m != null) {
                printWriter.print(str);
                printWriter.print("mBreadCrumbShortTitleRes=#");
                printWriter.print(Integer.toHexString(this.l));
                printWriter.print(" mBreadCrumbShortTitleText=");
                printWriter.println(this.m);
            }
        }
        ArrayList arrayList = this.a;
        if (arrayList.isEmpty()) {
            return;
        }
        printWriter.print(str);
        printWriter.println("Operations:");
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            r0 r0Var = (r0) arrayList.get(i);
            switch (r0Var.a) {
                case 0:
                    str2 = "NULL";
                    break;
                case 1:
                    str2 = "ADD";
                    break;
                case 2:
                    str2 = "REPLACE";
                    break;
                case 3:
                    str2 = "REMOVE";
                    break;
                case 4:
                    str2 = "HIDE";
                    break;
                case 5:
                    str2 = "SHOW";
                    break;
                case 6:
                    str2 = "DETACH";
                    break;
                case 7:
                    str2 = "ATTACH";
                    break;
                case 8:
                    str2 = "SET_PRIMARY_NAV";
                    break;
                case 9:
                    str2 = "UNSET_PRIMARY_NAV";
                    break;
                case 10:
                    str2 = "OP_SET_MAX_LIFECYCLE";
                    break;
                default:
                    str2 = "cmd=" + r0Var.a;
                    break;
            }
            printWriter.print(str);
            printWriter.print("  Op #");
            printWriter.print(i);
            printWriter.print(": ");
            printWriter.print(str2);
            printWriter.print(" ");
            printWriter.println(r0Var.b);
            if (z) {
                if (r0Var.d != 0 || r0Var.e != 0) {
                    printWriter.print(str);
                    printWriter.print("enterAnim=#");
                    printWriter.print(Integer.toHexString(r0Var.d));
                    printWriter.print(" exitAnim=#");
                    printWriter.println(Integer.toHexString(r0Var.e));
                }
                if (r0Var.f != 0 || r0Var.g != 0) {
                    printWriter.print(str);
                    printWriter.print("popEnterAnim=#");
                    printWriter.print(Integer.toHexString(r0Var.f));
                    printWriter.print(" popExitAnim=#");
                    printWriter.println(Integer.toHexString(r0Var.g));
                }
            }
        }
    }

    public final void k(Fragment fragment) {
        AbstractC1136h0 abstractC1136h0 = fragment.mFragmentManager;
        if (abstractC1136h0 == null || abstractC1136h0 == this.r) {
            c(new r0(fragment, 3));
            return;
        }
        throw new IllegalStateException("Cannot remove Fragment attached to a different FragmentManager. Fragment " + fragment.toString() + " is already attached to a FragmentManager.");
    }

    public final void l(int i, Fragment fragment, String str) {
        if (i == 0) {
            throw new IllegalArgumentException("Must use non-zero containerViewId");
        }
        i(i, fragment, str, 2);
    }

    public final void m(int i, int i2) {
        this.b = R.anim.slide_in_left;
        this.c = R.anim.slide_out_left;
        this.d = i;
        this.e = i2;
    }

    public final void n(Fragment fragment, androidx.lifecycle.B b) {
        AbstractC1136h0 abstractC1136h0 = fragment.mFragmentManager;
        AbstractC1136h0 abstractC1136h02 = this.r;
        if (abstractC1136h0 != abstractC1136h02) {
            throw new IllegalArgumentException("Cannot setMaxLifecycle for Fragment not attached to FragmentManager " + abstractC1136h02);
        }
        if (b == androidx.lifecycle.B.b && fragment.mState > -1) {
            throw new IllegalArgumentException("Cannot set maximum Lifecycle to " + b + " after the Fragment has been created");
        }
        if (b == androidx.lifecycle.B.a) {
            throw new IllegalArgumentException("Cannot set maximum Lifecycle to " + b + ". Use remove() to remove the fragment from the FragmentManager and trigger its destruction.");
        }
        r0 r0Var = new r0();
        r0Var.a = 10;
        r0Var.b = fragment;
        r0Var.c = false;
        r0Var.h = fragment.mMaxState;
        r0Var.i = b;
        c(r0Var);
    }

    public final String toString() {
        StringBuilder sbL = androidx.compose.ui.node.B.l(128, "BackStackEntry{");
        sbL.append(Integer.toHexString(System.identityHashCode(this)));
        if (this.t >= 0) {
            sbL.append(" #");
            sbL.append(this.t);
        }
        if (this.i != null) {
            sbL.append(" ");
            sbL.append(this.i);
        }
        sbL.append("}");
        return sbL.toString();
    }
}
