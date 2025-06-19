package androidx.transition;

import android.view.ViewGroup;
import androidx.collection.C0208f;
import com.quizlet.quizletandroid.R;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public abstract class C {
    public static final C1398a a;
    public static final ThreadLocal b;
    public static final ArrayList c;

    static {
        C1398a c1398a = new C1398a();
        c1398a.T(1);
        c1398a.R(new C1404g(2));
        c1398a.R(new C1402e());
        c1398a.R(new C1404g(1));
        a = c1398a;
        b = new ThreadLocal();
        c = new ArrayList();
    }

    public static void a(ViewGroup viewGroup, y yVar) {
        ArrayList arrayList = c;
        if (arrayList.contains(viewGroup) || !viewGroup.isLaidOut()) {
            return;
        }
        arrayList.add(viewGroup);
        if (yVar == null) {
            yVar = a;
        }
        y yVarClone = yVar.clone();
        c(viewGroup, yVarClone);
        viewGroup.setTag(R.id.transition_current_scene, null);
        B b2 = new B();
        b2.a = yVarClone;
        b2.b = viewGroup;
        viewGroup.addOnAttachStateChangeListener(b2);
        viewGroup.getViewTreeObserver().addOnPreDrawListener(b2);
    }

    public static C0208f b() {
        C0208f c0208f;
        ThreadLocal threadLocal = b;
        WeakReference weakReference = (WeakReference) threadLocal.get();
        if (weakReference != null && (c0208f = (C0208f) weakReference.get()) != null) {
            return c0208f;
        }
        C0208f c0208f2 = new C0208f(0);
        threadLocal.set(new WeakReference(c0208f2));
        return c0208f2;
    }

    public static void c(ViewGroup viewGroup, y yVar) {
        ArrayList arrayList = (ArrayList) b().get(viewGroup);
        if (arrayList != null && arrayList.size() > 0) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                ((y) it2.next()).A(viewGroup);
            }
        }
        if (yVar != null) {
            yVar.i(viewGroup, true);
        }
        if (viewGroup.getTag(R.id.transition_current_scene) != null) {
            throw new ClassCastException();
        }
    }
}
