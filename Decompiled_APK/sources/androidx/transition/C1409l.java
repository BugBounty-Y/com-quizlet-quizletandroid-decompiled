package androidx.transition;

import android.graphics.Rect;
import android.os.Build;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import androidx.appcompat.widget.C0122z;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.RunnableC1141k;
import androidx.fragment.app.RunnableC1152u;
import androidx.fragment.app.z0;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Objects;

/* renamed from: androidx.transition.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C1409l extends z0 {
    @Override // androidx.fragment.app.z0
    public final void a(View view, Object obj) {
        ((y) obj).c(view);
    }

    @Override // androidx.fragment.app.z0
    public final void b(Object obj, ArrayList arrayList) {
        y yVar = (y) obj;
        if (yVar == null) {
            return;
        }
        int i = 0;
        if (yVar instanceof F) {
            F f = (F) yVar;
            int size = f.F.size();
            while (i < size) {
                b(f.S(i), arrayList);
                i++;
            }
            return;
        }
        if (z0.k(yVar.e) && z0.k(yVar.f)) {
            int size2 = arrayList.size();
            while (i < size2) {
                yVar.c((View) arrayList.get(i));
                i++;
            }
        }
    }

    @Override // androidx.fragment.app.z0
    public final void c(Object obj) {
        C1418v c1418v = (C1418v) obj;
        c1418v.h();
        c1418v.d.a(c1418v.g.y + 1);
    }

    @Override // androidx.fragment.app.z0
    public final void d(Object obj, RunnableC1141k runnableC1141k) {
        C1418v c1418v = (C1418v) obj;
        c1418v.f = runnableC1141k;
        c1418v.h();
        c1418v.d.a(DefinitionKt.NO_Float_VALUE);
    }

    @Override // androidx.fragment.app.z0
    public final void e(ViewGroup viewGroup, Object obj) {
        C.a(viewGroup, (y) obj);
    }

    @Override // androidx.fragment.app.z0
    public final boolean g(Object obj) {
        return obj instanceof y;
    }

    @Override // androidx.fragment.app.z0
    public final Object h(Object obj) {
        if (obj != null) {
            return ((y) obj).clone();
        }
        return null;
    }

    @Override // androidx.fragment.app.z0
    public final Object i(ViewGroup viewGroup, Object obj) {
        y yVar = (y) obj;
        ArrayList arrayList = C.c;
        if (arrayList.contains(viewGroup) || !viewGroup.isLaidOut() || Build.VERSION.SDK_INT < 34) {
            return null;
        }
        if (!yVar.v()) {
            throw new IllegalArgumentException("The Transition must support seeking.");
        }
        arrayList.add(viewGroup);
        y yVarClone = yVar.clone();
        F f = new F();
        f.R(yVarClone);
        C.c(viewGroup, f);
        viewGroup.setTag(R.id.transition_current_scene, null);
        B b = new B();
        b.a = f;
        b.b = viewGroup;
        viewGroup.addOnAttachStateChangeListener(b);
        viewGroup.getViewTreeObserver().addOnPreDrawListener(b);
        viewGroup.invalidate();
        C1418v c1418v = new C1418v(f);
        f.z = c1418v;
        f.b(c1418v);
        return f.z;
    }

    @Override // androidx.fragment.app.z0
    public final boolean l() {
        return true;
    }

    @Override // androidx.fragment.app.z0
    public final boolean m(Object obj) {
        boolean zV = ((y) obj).v();
        if (!zV) {
            Objects.toString(obj);
        }
        return zV;
    }

    @Override // androidx.fragment.app.z0
    public final Object n(Object obj, Object obj2, Object obj3) {
        y yVar = (y) obj;
        y yVar2 = (y) obj2;
        y yVar3 = (y) obj3;
        if (yVar != null && yVar2 != null) {
            F f = new F();
            f.R(yVar);
            f.R(yVar2);
            f.T(1);
            yVar = f;
        } else if (yVar == null) {
            yVar = yVar2 != null ? yVar2 : null;
        }
        if (yVar3 == null) {
            return yVar;
        }
        F f2 = new F();
        if (yVar != null) {
            f2.R(yVar);
        }
        f2.R(yVar3);
        return f2;
    }

    @Override // androidx.fragment.app.z0
    public final Object o(Object obj, Object obj2) {
        F f = new F();
        if (obj != null) {
            f.R((y) obj);
        }
        f.R((y) obj2);
        return f;
    }

    @Override // androidx.fragment.app.z0
    public final void p(Object obj, View view, ArrayList arrayList) {
        ((y) obj).b(new C1406i(view, arrayList));
    }

    @Override // androidx.fragment.app.z0
    public final void q(Object obj, Object obj2, ArrayList arrayList, Object obj3, ArrayList arrayList2) {
        ((y) obj).b(new C1407j(this, obj2, arrayList, obj3, arrayList2));
    }

    @Override // androidx.fragment.app.z0
    public final void r(Object obj, float f) {
        C1418v c1418v = (C1418v) obj;
        boolean z = c1418v.b;
        if (z) {
            F f2 = c1418v.g;
            long j = f2.y;
            long j2 = (long) (f * j);
            if (j2 == 0) {
                j2 = 1;
            }
            if (j2 == j) {
                j2 = j - 1;
            }
            if (c1418v.d != null) {
                throw new IllegalStateException("setCurrentPlayTimeMillis() called after animation has been started");
            }
            long j3 = c1418v.a;
            if (j2 == j3 || !z) {
                return;
            }
            if (!c1418v.c) {
                if (j2 == 0 && j3 > 0) {
                    j2 = -1;
                } else if (j2 == j && j3 < j) {
                    j2 = j + 1;
                }
                if (j2 != j3) {
                    f2.H(j2, j3);
                    c1418v.a = j2;
                }
            }
            long jCurrentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
            C0122z c0122z = c1418v.e;
            int i = (c0122z.b + 1) % 20;
            c0122z.b = i;
            ((long[]) c0122z.c)[i] = jCurrentAnimationTimeMillis;
            ((float[]) c0122z.d)[i] = j2;
        }
    }

    @Override // androidx.fragment.app.z0
    public final void s(View view, Object obj) {
        if (view != null) {
            Rect rect = new Rect();
            z0.j(rect, view);
            ((y) obj).J(new C1405h(0, rect));
        }
    }

    @Override // androidx.fragment.app.z0
    public final void t(Object obj, Rect rect) {
        ((y) obj).J(new C1405h(1, rect));
    }

    @Override // androidx.fragment.app.z0
    public final void u(Fragment fragment, Object obj, androidx.core.os.b bVar, Runnable runnable) {
        v(obj, bVar, null, runnable);
    }

    @Override // androidx.fragment.app.z0
    public final void v(Object obj, androidx.core.os.b bVar, RunnableC1152u runnableC1152u, Runnable runnable) {
        y yVar = (y) obj;
        androidx.camera.camera2.internal.T t = new androidx.camera.camera2.internal.T(runnableC1152u, yVar, runnable, 5);
        synchronized (bVar) {
            while (bVar.b) {
                try {
                    try {
                        bVar.wait();
                    } catch (InterruptedException unused) {
                    }
                } finally {
                }
            }
            if (((androidx.camera.camera2.internal.T) bVar.c) != t) {
                bVar.c = t;
                if (bVar.a) {
                    RunnableC1152u runnableC1152u2 = (RunnableC1152u) t.b;
                    if (runnableC1152u2 == null) {
                        ((y) t.c).cancel();
                        ((Runnable) t.d).run();
                    } else {
                        runnableC1152u2.run();
                    }
                }
            }
        }
        yVar.b(new C1408k(runnable));
    }

    @Override // androidx.fragment.app.z0
    public final void w(Object obj, View view, ArrayList arrayList) {
        F f = (F) obj;
        ArrayList arrayList2 = f.f;
        arrayList2.clear();
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            z0.f((View) arrayList.get(i), arrayList2);
        }
        arrayList2.add(view);
        arrayList.add(view);
        b(f, arrayList);
    }

    @Override // androidx.fragment.app.z0
    public final void x(Object obj, ArrayList arrayList, ArrayList arrayList2) {
        F f = (F) obj;
        if (f != null) {
            ArrayList arrayList3 = f.f;
            arrayList3.clear();
            arrayList3.addAll(arrayList2);
            z(f, arrayList, arrayList2);
        }
    }

    @Override // androidx.fragment.app.z0
    public final Object y(Object obj) {
        if (obj == null) {
            return null;
        }
        F f = new F();
        f.R((y) obj);
        return f;
    }

    public final void z(Object obj, ArrayList arrayList, ArrayList arrayList2) {
        y yVar = (y) obj;
        int i = 0;
        if (yVar instanceof F) {
            F f = (F) yVar;
            int size = f.F.size();
            while (i < size) {
                z(f.S(i), arrayList, arrayList2);
                i++;
            }
            return;
        }
        if (z0.k(yVar.e)) {
            ArrayList arrayList3 = yVar.f;
            if (arrayList3.size() == arrayList.size() && arrayList3.containsAll(arrayList)) {
                int size2 = arrayList2 == null ? 0 : arrayList2.size();
                while (i < size2) {
                    yVar.c((View) arrayList2.get(i));
                    i++;
                }
                for (int size3 = arrayList.size() - 1; size3 >= 0; size3--) {
                    yVar.E((View) arrayList.get(size3));
                }
            }
        }
    }
}
