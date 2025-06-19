package androidx.savedstate;

import android.os.Bundle;
import androidx.appcompat.app.C0053i;
import androidx.compose.ui.platform.C0978y0;
import androidx.lifecycle.C1262x;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d {
    public final C0978y0 a;
    public C0053i b;

    public d(C0978y0 impl) {
        Intrinsics.checkNotNullParameter(impl, "impl");
        this.a = impl;
    }

    public final Bundle a(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        C0978y0 c0978y0 = this.a;
        Intrinsics.checkNotNullParameter(key, "key");
        if (!c0978y0.b) {
            throw new IllegalStateException("You can 'consumeRestoredStateForKey' only after the corresponding component has moved to the 'CREATED' state");
        }
        Bundle source = (Bundle) c0978y0.h;
        if (source == null) {
            return null;
        }
        Intrinsics.checkNotNullParameter(source, "source");
        Bundle bundleH = AbstractC3335e2.a(source, key) ? AbstractC3335e2.h(source, key) : null;
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(key, "key");
        source.remove(key);
        Intrinsics.checkNotNullParameter(source, "source");
        if (source.isEmpty()) {
            c0978y0.h = null;
        }
        return bundleH;
    }

    public final c b() {
        c cVar;
        Intrinsics.checkNotNullParameter("androidx.lifecycle.internal.SavedStateHandlesProvider", "key");
        C0978y0 c0978y0 = this.a;
        Intrinsics.checkNotNullParameter("androidx.lifecycle.internal.SavedStateHandlesProvider", "key");
        synchronized (((u) c0978y0.f)) {
            Iterator it2 = ((LinkedHashMap) c0978y0.g).entrySet().iterator();
            do {
                cVar = null;
                if (!it2.hasNext()) {
                    break;
                }
                Map.Entry entry = (Map.Entry) it2.next();
                String str = (String) entry.getKey();
                c cVar2 = (c) entry.getValue();
                if (Intrinsics.b(str, "androidx.lifecycle.internal.SavedStateHandlesProvider")) {
                    cVar = cVar2;
                }
            } while (cVar == null);
        }
        return cVar;
    }

    public final void c(String key, c provider) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(provider, "provider");
        C0978y0 c0978y0 = this.a;
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(provider, "provider");
        synchronized (((u) c0978y0.f)) {
            if (((LinkedHashMap) c0978y0.g).containsKey(key)) {
                throw new IllegalArgumentException("SavedStateProvider with the given key is already registered");
            }
            ((LinkedHashMap) c0978y0.g).put(key, provider);
            Unit unit = Unit.a;
        }
    }

    public final void d() throws NoSuchMethodException, SecurityException {
        Intrinsics.checkNotNullParameter(C1262x.class, "clazz");
        if (!this.a.c) {
            throw new IllegalStateException("Can not perform this action after onSaveInstanceState");
        }
        C0053i c0053i = this.b;
        if (c0053i == null) {
            c0053i = new C0053i(this);
        }
        this.b = c0053i;
        try {
            C1262x.class.getDeclaredConstructor(null);
            C0053i c0053i2 = this.b;
            if (c0053i2 != null) {
                String className = C1262x.class.getName();
                Intrinsics.checkNotNullExpressionValue(className, "getName(...)");
                Intrinsics.checkNotNullParameter(className, "className");
                ((LinkedHashSet) c0053i2.b).add(className);
            }
        } catch (NoSuchMethodException e) {
            throw new IllegalArgumentException("Class " + C1262x.class.getSimpleName() + " must have default constructor in order to be automatically recreated", e);
        }
    }
}
