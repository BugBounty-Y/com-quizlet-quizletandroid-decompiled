package androidx.savedstate;

import android.content.ContextWrapper;
import android.os.Bundle;
import androidx.activity.s;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.lifecycle.A;
import androidx.lifecycle.B0;
import androidx.lifecycle.C0;
import androidx.lifecycle.H;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import dagger.hilt.android.internal.managers.j;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a implements H {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ a(ContextWrapper contextWrapper, int i) {
        this.a = i;
        this.b = contextWrapper;
    }

    @Override // androidx.lifecycle.H
    public final void d(J source, A event) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(event, "event");
                if (event != A.ON_CREATE) {
                    throw new AssertionError("Next event must be ON_CREATE");
                }
                source.getLifecycle().b(this);
                f owner = (f) this.b;
                Bundle source2 = owner.getSavedStateRegistry().a("androidx.savedstate.Restarter");
                if (source2 == null) {
                    return;
                }
                Intrinsics.checkNotNullParameter(source2, "source");
                Intrinsics.checkNotNullParameter("classes_to_restore", "key");
                ArrayList<String> stringArrayList = source2.getStringArrayList("classes_to_restore");
                if (stringArrayList == null) {
                    throw new IllegalStateException("SavedState with restored state for the component \"androidx.savedstate.Restarter\" must contain list of strings by the key \"classes_to_restore\"");
                }
                for (String str : stringArrayList) {
                    try {
                        Class<? extends U> clsAsSubclass = Class.forName(str, false, a.class.getClassLoader()).asSubclass(b.class);
                        Intrinsics.d(clsAsSubclass);
                        try {
                            Constructor declaredConstructor = clsAsSubclass.getDeclaredConstructor(null);
                            declaredConstructor.setAccessible(true);
                            try {
                                Object objNewInstance = declaredConstructor.newInstance(null);
                                Intrinsics.d(objNewInstance);
                                Intrinsics.checkNotNullParameter(owner, "owner");
                                if (!(owner instanceof C0)) {
                                    throw new IllegalStateException(("Internal error: OnRecreation should be registered only on components that implement ViewModelStoreOwner. Received owner: " + owner).toString());
                                }
                                B0 viewModelStore = ((C0) owner).getViewModelStore();
                                d savedStateRegistry = owner.getSavedStateRegistry();
                                viewModelStore.getClass();
                                LinkedHashMap linkedHashMap = viewModelStore.a;
                                Iterator it2 = new HashSet(linkedHashMap.keySet()).iterator();
                                while (it2.hasNext()) {
                                    String key = (String) it2.next();
                                    Intrinsics.checkNotNullParameter(key, "key");
                                    w0 w0Var = (w0) linkedHashMap.get(key);
                                    if (w0Var != null) {
                                        p0.a(w0Var, savedStateRegistry, owner.getLifecycle());
                                    }
                                }
                                if (!new HashSet(linkedHashMap.keySet()).isEmpty()) {
                                    savedStateRegistry.d();
                                }
                            } catch (Exception e) {
                                throw new RuntimeException(AbstractC0147y.d("Failed to instantiate ", str), e);
                            }
                        } catch (NoSuchMethodException e2) {
                            throw new IllegalStateException("Class " + clsAsSubclass.getSimpleName() + " must have default constructor in order to be automatically recreated", e2);
                        }
                    } catch (ClassNotFoundException e3) {
                        throw new RuntimeException(android.support.v4.media.session.a.B("Class ", str, " wasn't found"), e3);
                    }
                }
                return;
            case 1:
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(event, "event");
                s sVar = (s) this.b;
                s.access$ensureViewModelStore(sVar);
                sVar.getLifecycle().b(this);
                return;
            default:
                if (event == A.ON_DESTROY) {
                    j jVar = (j) this.b;
                    jVar.getClass();
                    jVar.a = null;
                    jVar.b = null;
                    return;
                }
                return;
        }
    }

    public a(f owner) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(owner, "owner");
        this.b = owner;
    }
}
