package androidx.compose.ui.platform;

import android.content.Context;
import android.content.res.Configuration;
import android.os.Bundle;
import android.view.View;
import androidx.activity.C0034f;
import androidx.compose.foundation.gestures.C0346q0;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0775b0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0811n0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AndroidCompositionLocals_androidKt {
    public static final androidx.compose.runtime.B a = new androidx.compose.runtime.B(O.b);
    public static final androidx.compose.runtime.X0 b = new androidx.compose.runtime.X0(O.c);
    public static final androidx.compose.runtime.X0 c = new androidx.compose.runtime.X0(O.d);
    public static final androidx.compose.runtime.X0 d = new androidx.compose.runtime.X0(O.e);
    public static final androidx.compose.runtime.X0 e = new androidx.compose.runtime.X0(O.f);
    public static final androidx.compose.runtime.X0 f = new androidx.compose.runtime.X0(O.g);

    public static final void a(C0971v c0971v, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        InterfaceC0773a0 interfaceC0773a0;
        LinkedHashMap linkedHashMap;
        boolean z;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1396852028);
        if ((((c0814p.h(c0971v) ? 4 : 2) | i | (c0814p.h(dVar) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            Context context = c0971v.getContext();
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = C0776c.z(new Configuration(context.getResources().getConfiguration()));
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objI;
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new androidx.compose.foundation.gestures.T(interfaceC0773a02, 9);
                c0814p.i0(objI2);
            }
            c0971v.setConfigurationChangeObserver((Function1) objI2);
            Object objI3 = c0814p.I();
            if (objI3 == v) {
                objI3 = new C0935c0(context);
                c0814p.i0(objI3);
            }
            C0935c0 c0935c0 = (C0935c0) objI3;
            C0950k viewTreeOwners = c0971v.getViewTreeOwners();
            if (viewTreeOwners == null) {
                throw new IllegalStateException("Called when the ViewTreeOwnersAvailability is not yet in Available state");
            }
            Object objI4 = c0814p.I();
            androidx.savedstate.f fVar = viewTreeOwners.b;
            if (objI4 == v) {
                Object parent = c0971v.getParent();
                Intrinsics.e(parent, "null cannot be cast to non-null type android.view.View");
                View view = (View) parent;
                Object tag = view.getTag(R.id.compose_view_saveable_id_tag);
                String strValueOf = tag instanceof String ? (String) tag : null;
                if (strValueOf == null) {
                    strValueOf = String.valueOf(view.getId());
                }
                String str = androidx.compose.runtime.saveable.i.class.getSimpleName() + ':' + strValueOf;
                androidx.savedstate.d savedStateRegistry = fVar.getSavedStateRegistry();
                Bundle bundleA = savedStateRegistry.a(str);
                if (bundleA != null) {
                    linkedHashMap = new LinkedHashMap();
                    for (String str2 : bundleA.keySet()) {
                        ArrayList parcelableArrayList = bundleA.getParcelableArrayList(str2);
                        Intrinsics.e(parcelableArrayList, "null cannot be cast to non-null type java.util.ArrayList<kotlin.Any?>{ kotlin.collections.TypeAliasesKt.ArrayList<kotlin.Any?> }");
                        linkedHashMap.put(str2, parcelableArrayList);
                        interfaceC0773a02 = interfaceC0773a02;
                    }
                } else {
                    linkedHashMap = null;
                }
                interfaceC0773a0 = interfaceC0773a02;
                C0956n c0956n = C0956n.e;
                androidx.compose.runtime.X0 x0 = androidx.compose.runtime.saveable.k.a;
                androidx.compose.runtime.saveable.j jVar = new androidx.compose.runtime.saveable.j(linkedHashMap, c0956n);
                try {
                    savedStateRegistry.c(str, new C0034f(jVar, 1));
                    z = true;
                } catch (IllegalArgumentException unused) {
                    z = false;
                }
                C0961p0 c0961p0 = new C0961p0(jVar, new androidx.compose.foundation.text.L(z, savedStateRegistry, str));
                c0814p.i0(c0961p0);
                objI4 = c0961p0;
            } else {
                interfaceC0773a0 = interfaceC0773a02;
            }
            C0961p0 c0961p02 = (C0961p0) objI4;
            Unit unit = Unit.a;
            boolean zH = c0814p.h(c0961p02);
            Object objI5 = c0814p.I();
            if (zH || objI5 == v) {
                objI5 = new C0775b0(c0961p02, 18);
                c0814p.i0(objI5);
            }
            C0776c.d(unit, (Function1) objI5, c0814p);
            Configuration configuration = (Configuration) interfaceC0773a0.getValue();
            Object objI6 = c0814p.I();
            if (objI6 == v) {
                objI6 = new androidx.compose.ui.res.c();
                c0814p.i0(objI6);
            }
            androidx.compose.ui.res.c cVar = (androidx.compose.ui.res.c) objI6;
            Object objI7 = c0814p.I();
            Object obj = objI7;
            if (objI7 == v) {
                Configuration configuration2 = new Configuration();
                if (configuration != null) {
                    configuration2.setTo(configuration);
                }
                c0814p.i0(configuration2);
                obj = configuration2;
            }
            Configuration configuration3 = (Configuration) obj;
            Object objI8 = c0814p.I();
            if (objI8 == v) {
                objI8 = new P(configuration3, cVar);
                c0814p.i0(objI8);
            }
            P p = (P) objI8;
            boolean zH2 = c0814p.h(context);
            Object objI9 = c0814p.I();
            if (zH2 || objI9 == v) {
                objI9 = new androidx.compose.foundation.text.selection.n0(19, context, p);
                c0814p.i0(objI9);
            }
            C0776c.d(cVar, (Function1) objI9, c0814p);
            Object objI10 = c0814p.I();
            if (objI10 == v) {
                objI10 = new androidx.compose.ui.res.d();
                c0814p.i0(objI10);
            }
            androidx.compose.ui.res.d dVar2 = (androidx.compose.ui.res.d) objI10;
            Object objI11 = c0814p.I();
            if (objI11 == v) {
                objI11 = new Q(dVar2);
                c0814p.i0(objI11);
            }
            Q q = (Q) objI11;
            boolean zH3 = c0814p.h(context);
            Object objI12 = c0814p.I();
            if (zH3 || objI12 == v) {
                objI12 = new androidx.compose.foundation.text.selection.n0(20, context, q);
                c0814p.i0(objI12);
            }
            C0776c.d(dVar2, (Function1) objI12, c0814p);
            androidx.compose.runtime.B b2 = AbstractC0955m0.t;
            C0776c.b(new C0811n0[]{a.a((Configuration) interfaceC0773a0.getValue()), b.a(context), androidx.lifecycle.compose.g.a.a(viewTreeOwners.a), e.a(fVar), androidx.compose.runtime.saveable.k.a.a(c0961p02), f.a(c0971v.getView()), c.a(cVar), d.a(dVar2), b2.a(Boolean.valueOf(((Boolean) c0814p.j(b2)).booleanValue() | c0971v.getScrollCaptureInProgress$ui_release()))}, androidx.compose.runtime.internal.e.e(1471621628, new C0346q0(c0971v, c0935c0, dVar, 7), c0814p), c0814p, 56);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.foundation.contextmenu.i(c0971v, dVar, i, 24);
        }
    }

    public static final void b(String str) {
        throw new IllegalStateException(("CompositionLocal " + str + " not present").toString());
    }

    @NotNull
    public static final AbstractC0809m0 getLocalLifecycleOwner() {
        return androidx.lifecycle.compose.g.a;
    }

    @NotNull
    public static final AbstractC0809m0 getLocalSavedStateRegistryOwner() {
        return e;
    }
}
