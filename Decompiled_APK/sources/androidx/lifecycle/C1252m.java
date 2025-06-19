package androidx.lifecycle;

import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.UI.fragment.ViewOnClickListenerC4058b;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.lifecycle.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1252m implements H {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ C1252m(androidx.fragment.app.I i, com.google.android.material.bottomsheet.i iVar, int i2) {
        this.a = i2;
        this.b = iVar;
        this.c = i;
    }

    @Override // androidx.lifecycle.H
    public final void d(J source, A event) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(event, "event");
                int i = AbstractC1251l.a[event.ordinal()];
                InterfaceC1250k interfaceC1250k = (InterfaceC1250k) this.b;
                switch (i) {
                    case 1:
                        interfaceC1250k.onCreate(source);
                        break;
                    case 2:
                        interfaceC1250k.onStart(source);
                        break;
                    case 3:
                        interfaceC1250k.onResume(source);
                        break;
                    case 4:
                        interfaceC1250k.onPause(source);
                        break;
                    case 5:
                        interfaceC1250k.onStop(source);
                        break;
                    case 6:
                        interfaceC1250k.onDestroy(source);
                        break;
                    case 7:
                        throw new IllegalArgumentException("ON_ANY must not been send by anybody");
                    default:
                        throw new NoWhenBranchMatchedException();
                }
                H h = (H) this.c;
                if (h != null) {
                    h.d(source, event);
                    return;
                }
                return;
            case 1:
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(event, "event");
                if (event == A.ON_START) {
                    ((C) this.b).b(this);
                    ((androidx.savedstate.d) this.c).d();
                    return;
                }
                return;
            case 2:
                HashMap map = ((C1243d) this.c).a;
                List list = (List) map.get(event);
                I i2 = (I) this.b;
                C1243d.a(list, source, event, i2);
                C1243d.a((List) map.get(A.ON_ANY), source, event, i2);
                return;
            case 3:
                if (event.compareTo(A.ON_RESUME) == 0) {
                    androidx.fragment.app.I i3 = (androidx.fragment.app.I) this.c;
                    ((ViewOnClickListenerC4058b) this.b).O(i3.getSupportFragmentManager(), OTFragmentTags.OT_AGE_GATE_FRAGMENT_TAG);
                    i3.getLifecycle().b(this);
                    return;
                }
                return;
            default:
                if (event.compareTo(A.ON_RESUME) == 0) {
                    androidx.fragment.app.I i4 = (androidx.fragment.app.I) this.c;
                    ((com.onetrust.otpublishers.headless.UI.fragment.u) this.b).O(i4.getSupportFragmentManager(), OTFragmentTags.OT_UC_PURPOSES_FRAGMENT_TAG);
                    i4.getLifecycle().b(this);
                    return;
                }
                return;
        }
    }

    public C1252m(InterfaceC1250k defaultLifecycleObserver, H h) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(defaultLifecycleObserver, "defaultLifecycleObserver");
        this.b = defaultLifecycleObserver;
        this.c = h;
    }

    public C1252m(I i) {
        this.a = 2;
        this.b = i;
        C1245f c1245f = C1245f.c;
        Class<?> cls = i.getClass();
        C1243d c1243d = (C1243d) c1245f.a.get(cls);
        this.c = c1243d == null ? c1245f.a(cls, null) : c1243d;
    }

    public C1252m(C c, androidx.savedstate.d dVar) {
        this.a = 1;
        this.b = c;
        this.c = dVar;
    }
}
