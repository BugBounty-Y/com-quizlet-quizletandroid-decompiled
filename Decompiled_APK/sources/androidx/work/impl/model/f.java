package androidx.work.impl.model;

import android.view.Menu;
import android.view.MenuItem;
import androidx.activity.L;
import androidx.activity.N;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.C0839z;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.J;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public abstract class f {
    public static final /* synthetic */ int a = 0;

    public static final void a(boolean z, Function2 function2, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-642000585);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function2) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D(function2, c0814p);
            Object objI = c0814p.I();
            V v = C0804k.a;
            if (objI == v) {
                objI = android.support.v4.media.session.a.c(C0776c.n(kotlin.coroutines.n.a, c0814p), c0814p);
            }
            C c = ((C0839z) objI).a;
            Object objI2 = c0814p.I();
            Object obj = objI2;
            if (objI2 == v) {
                Function2 function22 = (Function2) interfaceC0773a0D.getValue();
                androidx.activity.compose.r rVar = new androidx.activity.compose.r(z);
                rVar.d = c;
                rVar.e = function22;
                c0814p.i0(rVar);
                obj = rVar;
            }
            androidx.activity.compose.r rVar2 = (androidx.activity.compose.r) obj;
            boolean zF = c0814p.f((Function2) interfaceC0773a0D.getValue()) | c0814p.f(c);
            Object objI3 = c0814p.I();
            if (zF || objI3 == v) {
                rVar2.e = (Function2) interfaceC0773a0D.getValue();
                rVar2.d = c;
                c0814p.i0(Unit.a);
            }
            Boolean boolValueOf = Boolean.valueOf(z);
            boolean zH = ((i2 & 14) == 4) | c0814p.h(rVar2);
            Object objI4 = c0814p.I();
            if (zH || objI4 == v) {
                objI4 = new androidx.activity.compose.s(rVar2, z, null);
                c0814p.i0(objI4);
            }
            C0776c.f(c0814p, boolValueOf, (Function2) objI4);
            N nA = androidx.activity.compose.n.a(c0814p);
            if (nA == null) {
                throw new IllegalStateException("No OnBackPressedDispatcherOwner was provided via LocalOnBackPressedDispatcherOwner");
            }
            L onBackPressedDispatcher = nA.getOnBackPressedDispatcher();
            J j = (J) c0814p.j(AndroidCompositionLocals_androidKt.getLocalLifecycleOwner());
            boolean zH2 = c0814p.h(onBackPressedDispatcher) | c0814p.h(j) | c0814p.h(rVar2);
            Object objI5 = c0814p.I();
            if (zH2 || objI5 == v) {
                objI5 = new androidx.activity.compose.g(onBackPressedDispatcher, j, rVar2, 1);
                c0814p.i0(objI5);
            }
            C0776c.c(j, onBackPressedDispatcher, (Function1) objI5, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.activity.compose.t(z, function2, i);
        }
    }

    public static final void b(Menu menu, int i, boolean z) {
        Intrinsics.checkNotNullParameter(menu, "<this>");
        MenuItem menuItemFindItem = menu.findItem(i);
        if (menuItemFindItem == null || menuItemFindItem.setVisible(z) == null) {
            timber.log.c.a.e(new NullPointerException(AbstractC0147y.c(i, "MenuItem [id: ", "] is null")));
            Unit unit = Unit.a;
        }
    }
}
