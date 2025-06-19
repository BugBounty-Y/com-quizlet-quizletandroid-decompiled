package androidx.lifecycle;

import android.app.Application;
import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_camera.A1;
import java.lang.reflect.Constructor;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class s0 implements y0 {
    public final Application a;
    public final x0 b;
    public final Bundle c;
    public final C d;
    public final androidx.savedstate.d e;

    public s0() {
        this.b = new x0(null);
    }

    @Override // androidx.lifecycle.y0
    public final w0 a(Class modelClass) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        String canonicalName = modelClass.getCanonicalName();
        if (canonicalName != null) {
            return d(modelClass, canonicalName);
        }
        throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
    }

    @Override // androidx.lifecycle.y0
    public final w0 b(Class modelClass, androidx.lifecycle.viewmodel.e extras) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(extras, "extras");
        String str = (String) extras.a(A0.b);
        if (str == null) {
            throw new IllegalStateException("VIEW_MODEL_KEY must always be provided by ViewModelProvider");
        }
        if (extras.a(p0.a) == null || extras.a(p0.b) == null) {
            if (this.d != null) {
                return d(modelClass, str);
            }
            throw new IllegalStateException("SAVED_STATE_REGISTRY_OWNER_KEY andVIEW_MODEL_STORE_OWNER_KEY must be provided in the creation extras tosuccessfully create a ViewModel.");
        }
        Application application = (Application) extras.a(x0.d);
        boolean zIsAssignableFrom = AbstractC1237a.class.isAssignableFrom(modelClass);
        Constructor constructorA = (!zIsAssignableFrom || application == null) ? t0.a(modelClass, t0.b) : t0.a(modelClass, t0.a);
        return constructorA == null ? this.b.b(modelClass, extras) : (!zIsAssignableFrom || application == null) ? t0.b(modelClass, constructorA, p0.c(extras)) : t0.b(modelClass, constructorA, application, p0.c(extras));
    }

    @Override // androidx.lifecycle.y0
    public final w0 c(C4950i modelClass, androidx.lifecycle.viewmodel.e extras) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(extras, "extras");
        return b(kotlin.jvm.a.b(modelClass), extras);
    }

    public final w0 d(Class modelClass, String key) throws NoSuchMethodException, SecurityException {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        C lifecycle = this.d;
        if (lifecycle == null) {
            throw new UnsupportedOperationException("SavedStateViewModelFactory constructed with empty constructor supports only calls to create(modelClass: Class<T>, extras: CreationExtras).");
        }
        boolean zIsAssignableFrom = AbstractC1237a.class.isAssignableFrom(modelClass);
        Application application = this.a;
        Constructor constructorA = (!zIsAssignableFrom || application == null) ? t0.a(modelClass, t0.b) : t0.a(modelClass, t0.a);
        if (constructorA == null) {
            if (application != null) {
                return this.b.a(modelClass);
            }
            if (z0.a == null) {
                z0.a = new z0();
            }
            Intrinsics.d(z0.a);
            Intrinsics.checkNotNullParameter(modelClass, "modelClass");
            return A1.h(modelClass);
        }
        androidx.savedstate.d registry = this.e;
        Intrinsics.d(registry);
        Intrinsics.checkNotNullParameter(registry, "registry");
        Intrinsics.checkNotNullParameter(lifecycle, "lifecycle");
        m0 m0VarB = p0.b(registry.a(key), this.c);
        n0 n0Var = new n0(key, m0VarB);
        n0Var.a(lifecycle, registry);
        B b = ((L) lifecycle).d;
        if (b == B.b || b.a(B.d)) {
            registry.d();
        } else {
            lifecycle.a(new C1252m(lifecycle, registry));
        }
        w0 w0VarB = (!zIsAssignableFrom || application == null) ? t0.b(modelClass, constructorA, m0VarB) : t0.b(modelClass, constructorA, application, m0VarB);
        w0VarB.w(n0Var, "androidx.lifecycle.savedstate.vm.tag");
        return w0VarB;
    }

    public s0(Application application, androidx.savedstate.f owner, Bundle bundle) {
        x0 x0Var;
        Intrinsics.checkNotNullParameter(owner, "owner");
        this.e = owner.getSavedStateRegistry();
        this.d = owner.getLifecycle();
        this.c = bundle;
        this.a = application;
        if (application != null) {
            Intrinsics.checkNotNullParameter(application, "application");
            if (x0.c == null) {
                Intrinsics.checkNotNullParameter(application, "application");
                x0.c = new x0(application);
            }
            x0Var = x0.c;
            Intrinsics.d(x0Var);
        } else {
            x0Var = new x0(null);
        }
        this.b = x0Var;
    }
}
