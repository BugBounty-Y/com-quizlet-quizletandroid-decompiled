package androidx.paging;

import androidx.compose.material.C0574q;
import androidx.datastore.core.C1087t;
import com.android.billingclient.api.C1472a;
import java.util.List;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.C5013v;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* renamed from: androidx.paging.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1348x {
    public static final Object a = new Object();

    public static L a(List pages, int i, int i2, F sourceLoadStates, F f) {
        Intrinsics.checkNotNullParameter(pages, "pages");
        Intrinsics.checkNotNullParameter(sourceLoadStates, "sourceLoadStates");
        return new L(G.a, pages, i, i2, sourceLoadStates, f);
    }

    public static final kotlinx.coroutines.flow.Y b(InterfaceC4992i interfaceC4992i, androidx.lifecycle.viewmodel.internal.a scope) {
        Intrinsics.checkNotNullParameter(interfaceC4992i, "<this>");
        Intrinsics.checkNotNullParameter(scope, "scope");
        Intrinsics.checkNotNullParameter(interfaceC4992i, "<this>");
        Intrinsics.checkNotNullParameter(scope, "scope");
        kotlin.coroutines.h hVar = null;
        InterfaceC4992i interfaceC4992iF = f(interfaceC4992i, new C1319i(hVar, scope, 0));
        int i = 3;
        C0574q operation = new C0574q(i, 4, hVar);
        Intrinsics.checkNotNullParameter(interfaceC4992iF, "<this>");
        Intrinsics.checkNotNullParameter(operation, "operation");
        C5013v c5013v = new C5013v(new J0(new C1321j(2, null), new C1087t(new C1087t(new C1338s(interfaceC4992iF, operation, null)), 1)), new androidx.compose.foundation.gestures.S(i, 3, hVar));
        kotlinx.coroutines.flow.j0 j0Var = kotlinx.coroutines.flow.h0.b;
        com.google.android.gms.cloudmessaging.k kVarJ = kotlinx.coroutines.flow.e0.j(c5013v, 1);
        kotlinx.coroutines.flow.d0 d0VarA = kotlinx.coroutines.flow.e0.a(1, kVarJ.b, (kotlinx.coroutines.channels.a) kVarJ.d);
        C1472a c1472a = kotlinx.coroutines.flow.e0.a;
        InterfaceC4992i interfaceC4992i2 = (InterfaceC4992i) kVarJ.c;
        kotlinx.coroutines.E.z(scope, (CoroutineContext) kVarJ.e, j0Var.equals(kotlinx.coroutines.flow.h0.a) ? kotlinx.coroutines.D.a : kotlinx.coroutines.D.d, new kotlinx.coroutines.flow.Q(j0Var, interfaceC4992i2, d0VarA, c1472a, null));
        return new kotlinx.coroutines.flow.Y(d0VarA);
    }

    public static final C1351y0 c(C1351y0 c1351y0, Function2 transform) {
        Intrinsics.checkNotNullParameter(c1351y0, "<this>");
        Intrinsics.checkNotNullParameter(transform, "transform");
        return new C1351y0(new J0(c1351y0.a, transform, 0), c1351y0.b, c1351y0.c, C1349x0.a);
    }

    public static final boolean d(k1 k1Var, k1 k1Var2, G loadType) {
        Intrinsics.checkNotNullParameter(k1Var, "<this>");
        Intrinsics.checkNotNullParameter(loadType, "loadType");
        if (k1Var2 == null || ((k1Var2 instanceof j1) && (k1Var instanceof i1))) {
            return true;
        }
        if ((k1Var instanceof j1) && (k1Var2 instanceof i1)) {
            return false;
        }
        return (k1Var.c == k1Var2.c && k1Var.d == k1Var2.d && k1Var2.a(loadType) <= k1Var.a(loadType)) ? false : true;
    }

    public static final InterfaceC4992i e(Function2 block) {
        Intrinsics.checkNotNullParameter(block, "block");
        return kotlinx.coroutines.flow.e0.f(new C1087t(new Z0(block, null)), -2);
    }

    public static final InterfaceC4992i f(InterfaceC4992i interfaceC4992i, kotlin.jvm.functions.c transform) {
        Intrinsics.checkNotNullParameter(interfaceC4992i, "<this>");
        Intrinsics.checkNotNullParameter(transform, "transform");
        return e(new C1346w(interfaceC4992i, transform, null));
    }
}
