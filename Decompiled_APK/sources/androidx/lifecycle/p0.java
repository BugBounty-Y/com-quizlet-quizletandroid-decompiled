package androidx.lifecycle;

import android.os.Bundle;
import android.view.View;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3315z6;
import com.quizlet.quizletandroid.R;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.C4986c;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes.dex */
public abstract class p0 {
    public static final com.google.firebase.heartbeatinfo.e a = new com.google.firebase.heartbeatinfo.e(4);
    public static final com.google.firebase.perf.logging.b b = new com.google.firebase.perf.logging.b(4);
    public static final com.google.mlkit.common.internal.model.a c = new com.google.mlkit.common.internal.model.a(4);
    public static final androidx.lifecycle.viewmodel.internal.c d = new androidx.lifecycle.viewmodel.internal.c();

    public static final void a(w0 viewModel, androidx.savedstate.d registry, C lifecycle) throws NoSuchMethodException, SecurityException {
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        Intrinsics.checkNotNullParameter(registry, "registry");
        Intrinsics.checkNotNullParameter(lifecycle, "lifecycle");
        n0 n0Var = (n0) viewModel.y("androidx.lifecycle.savedstate.vm.tag");
        if (n0Var == null || n0Var.c) {
            return;
        }
        n0Var.a(lifecycle, registry);
        B b2 = ((L) lifecycle).d;
        if (b2 == B.b || b2.a(B.d)) {
            registry.d();
        } else {
            lifecycle.a(new C1252m(lifecycle, registry));
        }
    }

    public static m0 b(Bundle source, Bundle bundle) {
        if (source == null) {
            source = bundle;
        }
        if (source == null) {
            return new m0();
        }
        ClassLoader classLoader = m0.class.getClassLoader();
        Intrinsics.d(classLoader);
        source.setClassLoader(classLoader);
        Intrinsics.checkNotNullParameter(source, "source");
        kotlin.collections.builders.h builder = new kotlin.collections.builders.h(source.size());
        for (String str : source.keySet()) {
            Intrinsics.d(str);
            builder.put(str, source.get(str));
        }
        Intrinsics.checkNotNullParameter(builder, "builder");
        return new m0(builder.b());
    }

    public static final m0 c(androidx.lifecycle.viewmodel.c cVar) {
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        androidx.savedstate.f fVar = (androidx.savedstate.f) cVar.a(a);
        if (fVar == null) {
            throw new IllegalArgumentException("CreationExtras must have a value by `SAVED_STATE_REGISTRY_OWNER_KEY`");
        }
        C0 c0 = (C0) cVar.a(b);
        if (c0 == null) {
            throw new IllegalArgumentException("CreationExtras must have a value by `VIEW_MODEL_STORE_OWNER_KEY`");
        }
        Bundle bundle = (Bundle) cVar.a(c);
        String key = (String) cVar.a(A0.b);
        if (key == null) {
            throw new IllegalArgumentException("CreationExtras must have a value by `VIEW_MODEL_KEY`");
        }
        Intrinsics.checkNotNullParameter(fVar, "<this>");
        androidx.savedstate.c cVarB = fVar.getSavedStateRegistry().b();
        Bundle bundle2 = null;
        q0 q0Var = cVarB instanceof q0 ? (q0) cVarB : null;
        if (q0Var == null) {
            throw new IllegalStateException("enableSavedStateHandles() wasn't called prior to createSavedStateHandle() call");
        }
        r0 r0VarI = i(c0);
        m0 m0Var = (m0) r0VarI.b.get(key);
        if (m0Var != null) {
            return m0Var;
        }
        Intrinsics.checkNotNullParameter(key, "key");
        q0Var.b();
        Bundle source = q0Var.c;
        if (source != null) {
            Intrinsics.checkNotNullParameter(source, "source");
            Intrinsics.checkNotNullParameter(key, "key");
            if (source.containsKey(key)) {
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(key, "key");
                Bundle source2 = source.getBundle(key);
                if (source2 == null) {
                    kotlin.collections.V.c();
                    source2 = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
                    Intrinsics.checkNotNullParameter(source2, "source");
                }
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(key, "key");
                source.remove(key);
                Intrinsics.checkNotNullParameter(source, "source");
                if (source.isEmpty()) {
                    q0Var.c = null;
                }
                bundle2 = source2;
            }
        }
        m0 m0VarB = b(bundle2, bundle);
        r0VarI.b.put(key, m0VarB);
        return m0VarB;
    }

    public static final void d(androidx.savedstate.f fVar) {
        Intrinsics.checkNotNullParameter(fVar, "<this>");
        B b2 = ((L) fVar.getLifecycle()).d;
        if (b2 != B.b && b2 != B.c) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        if (fVar.getSavedStateRegistry().b() == null) {
            q0 q0Var = new q0(fVar.getSavedStateRegistry(), (C0) fVar);
            fVar.getSavedStateRegistry().c("androidx.lifecycle.internal.SavedStateHandlesProvider", q0Var);
            fVar.getLifecycle().a(new C1246g(q0Var));
        }
    }

    public static final C4986c e(InterfaceC4992i interfaceC4992i, C lifecycle, B minActiveState) {
        Intrinsics.checkNotNullParameter(interfaceC4992i, "<this>");
        Intrinsics.checkNotNullParameter(lifecycle, "lifecycle");
        Intrinsics.checkNotNullParameter(minActiveState, "minActiveState");
        return kotlinx.coroutines.flow.e0.g(new C1256q(lifecycle, minActiveState, interfaceC4992i, null));
    }

    public static final J f(View view) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        while (view != null) {
            Object tag = view.getTag(R.id.view_tree_lifecycle_owner);
            J j = tag instanceof J ? (J) tag : null;
            if (j != null) {
                return j;
            }
            Object objB = AbstractC3315z6.b(view);
            view = objB instanceof View ? (View) objB : null;
        }
        return null;
    }

    public static final C0 g(View view) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        while (view != null) {
            Object tag = view.getTag(R.id.view_tree_view_model_store_owner);
            C0 c0 = tag instanceof C0 ? (C0) tag : null;
            if (c0 != null) {
                return c0;
            }
            Object objB = AbstractC3315z6.b(view);
            view = objB instanceof View ? (View) objB : null;
        }
        return null;
    }

    public static final E h(J j) {
        Intrinsics.checkNotNullParameter(j, "<this>");
        C lifecycle = j.getLifecycle();
        Intrinsics.checkNotNullParameter(lifecycle, "<this>");
        while (true) {
            E e = (E) ((AtomicReference) lifecycle.a.a).get();
            if (e != null) {
                return e;
            }
            kotlinx.coroutines.A0 a0E = kotlinx.coroutines.E.e();
            kotlinx.coroutines.scheduling.e eVar = kotlinx.coroutines.O.a;
            E e2 = new E(lifecycle, kotlin.coroutines.k.c(kotlinx.coroutines.internal.m.a.e, a0E));
            AtomicReference atomicReference = (AtomicReference) lifecycle.a.a;
            while (!atomicReference.compareAndSet(null, e2)) {
                if (atomicReference.get() != null) {
                    break;
                }
            }
            kotlinx.coroutines.scheduling.e eVar2 = kotlinx.coroutines.O.a;
            kotlinx.coroutines.E.A(e2, kotlinx.coroutines.internal.m.a.e, null, new D(e2, null), 2);
            return e2;
        }
    }

    public static final r0 i(C0 c0) {
        Intrinsics.checkNotNullParameter(c0, "<this>");
        A0 a0P = com.google.mlkit.common.sdkinternal.model.a.p(c0, new o0(), 4);
        C4950i modelClass = kotlin.jvm.internal.K.a(r0.class);
        Intrinsics.checkNotNullParameter("androidx.lifecycle.internal.SavedStateHandlesVM", "key");
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        return (r0) ((com.quizlet.data.repository.metering.j) a0P.a).e(modelClass, "androidx.lifecycle.internal.SavedStateHandlesVM");
    }

    public static final androidx.lifecycle.viewmodel.internal.a j(w0 w0Var) {
        androidx.lifecycle.viewmodel.internal.a aVar;
        CoroutineContext coroutineContext;
        Intrinsics.checkNotNullParameter(w0Var, "<this>");
        synchronized (d) {
            aVar = (androidx.lifecycle.viewmodel.internal.a) w0Var.y("androidx.lifecycle.viewmodel.internal.ViewModelCoroutineScope.JOB_KEY");
            if (aVar == null) {
                try {
                    try {
                        kotlinx.coroutines.scheduling.e eVar = kotlinx.coroutines.O.a;
                        coroutineContext = kotlinx.coroutines.internal.m.a.e;
                    } catch (kotlin.n unused) {
                        coroutineContext = kotlin.coroutines.n.a;
                    }
                } catch (IllegalStateException unused2) {
                    coroutineContext = kotlin.coroutines.n.a;
                }
                androidx.lifecycle.viewmodel.internal.a aVar2 = new androidx.lifecycle.viewmodel.internal.a(coroutineContext.plus(kotlinx.coroutines.E.e()));
                w0Var.w(aVar2, "androidx.lifecycle.viewmodel.internal.ViewModelCoroutineScope.JOB_KEY");
                aVar = aVar2;
            }
        }
        return aVar;
    }

    public static final X k(Y y, Function1 transform) {
        X x;
        Intrinsics.checkNotNullParameter(y, "<this>");
        Intrinsics.checkNotNullParameter(transform, "transform");
        if (y.e != T.k) {
            x = new X(transform.invoke(y.d()));
            x.m = new androidx.arch.core.internal.f();
        } else {
            x = new X(0);
        }
        x.m(y, new v0(new u0(0, (Object) x, (Object) transform)));
        return x;
    }

    public static final Object l(C c2, B b2, Function2 function2, kotlin.coroutines.h hVar) {
        Object objM;
        if (b2 != B.b) {
            return (((L) c2).d != B.a && (objM = kotlinx.coroutines.E.m(new i0(c2, b2, function2, null), hVar)) == kotlin.coroutines.intrinsics.a.a) ? objM : Unit.a;
        }
        throw new IllegalArgumentException("repeatOnLifecycle cannot start work with the INITIALIZED lifecycle state.");
    }

    public static final Object m(J j, B b2, Function2 function2, kotlin.coroutines.h hVar) {
        Object objL = l(j.getLifecycle(), b2, function2, hVar);
        return objL == kotlin.coroutines.intrinsics.a.a ? objL : Unit.a;
    }

    public static final void n(View view, J j) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setTag(R.id.view_tree_lifecycle_owner, j);
    }

    public static final void o(View view, C0 c0) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setTag(R.id.view_tree_view_model_store_owner, c0);
    }
}
