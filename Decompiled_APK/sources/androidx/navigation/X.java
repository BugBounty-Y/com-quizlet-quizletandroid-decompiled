package androidx.navigation;

import com.google.android.gms.internal.mlkit_vision_camera.K1;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class X {
    public static final LinkedHashMap b = new LinkedHashMap();
    public final LinkedHashMap a = new LinkedHashMap();

    public final void a(W navigator) {
        Intrinsics.checkNotNullParameter(navigator, "navigator");
        String name = K1.h(navigator.getClass());
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(navigator, "navigator");
        if (name.length() <= 0) {
            throw new IllegalArgumentException("navigator name cannot be an empty string");
        }
        LinkedHashMap linkedHashMap = this.a;
        W w = (W) linkedHashMap.get(name);
        if (Intrinsics.b(w, navigator)) {
            return;
        }
        boolean z = false;
        if (w != null && w.b) {
            z = true;
        }
        if (z) {
            throw new IllegalStateException(("Navigator " + navigator + " is replacing an already attached " + w).toString());
        }
        if (!navigator.b) {
            return;
        }
        throw new IllegalStateException(("Navigator " + navigator + " is already attached to another NavController").toString());
    }

    public final W b(Class navigatorClass) {
        Intrinsics.checkNotNullParameter(navigatorClass, "navigatorClass");
        return c(K1.h(navigatorClass));
    }

    public final W c(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        if (name == null || name.length() <= 0) {
            throw new IllegalArgumentException("navigator name cannot be an empty string");
        }
        W w = (W) this.a.get(name);
        if (w != null) {
            return w;
        }
        throw new IllegalStateException(android.support.v4.media.session.a.B("Could not find Navigator with name \"", name, "\". You must call NavController.addNavigator() for each navigation type."));
    }
}
