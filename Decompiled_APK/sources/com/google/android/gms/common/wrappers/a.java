package com.google.android.gms.common.wrappers;

import android.content.Context;
import android.hardware.camera2.CameraCharacteristics;
import android.os.Build;
import androidx.camera.camera2.internal.C0132i;
import androidx.camera.camera2.internal.compat.k;
import androidx.camera.camera2.internal.compat.quirk.FlashAvailabilityBufferUnderflowQuirk;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.foundation.layout.S0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.internal.d;
import androidx.compose.ui.n;
import androidx.compose.ui.platform.N;
import androidx.compose.ui.q;
import androidx.lifecycle.B;
import androidx.lifecycle.C0;
import androidx.lifecycle.InterfaceC1261w;
import androidx.lifecycle.J;
import androidx.lifecycle.compose.e;
import androidx.lifecycle.compose.g;
import androidx.navigation.compose.C1280m;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.assembly.compose.input.m;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.achievements.data.h;
import com.quizlet.features.achievements.ui.composables.A;
import com.quizlet.features.achievements.ui.composables.C;
import com.quizlet.features.achievements.ui.composables.D;
import com.quizlet.features.achievements.ui.composables.E;
import com.quizlet.quizletandroid.R;
import dagger.hilt.android.internal.lifecycle.f;
import java.nio.BufferUnderflowException;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes2.dex */
public abstract class a {
    public static Context a;
    public static Boolean b;

    public static final void a(Function0 function0, Function1 function1, com.quizlet.features.achievements.viewmodel.c cVar, InterfaceC0806l interfaceC0806l, int i) {
        Function1 function12;
        int i2;
        Object obj;
        Function1 function13;
        Object obj2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1075512256);
        int i3 = i | (c0814p.h(function0) ? 4 : 2) | 176;
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            function13 = function1;
            obj2 = cVar;
        } else {
            c0814p.S();
            int i4 = i & 1;
            Object obj3 = C0804k.a;
            if (i4 == 0 || c0814p.w()) {
                c0814p.X(-2041295162);
                Object objI = c0814p.I();
                if (objI == obj3) {
                    objI = new Z(28);
                    c0814p.i0(objI);
                }
                function12 = (Function1) objI;
                c0814p.p(false);
                c0814p.Y(1890788296);
                C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                Object objE = AbstractC3417z1.e(com.quizlet.features.achievements.viewmodel.b.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-897);
                obj = (com.quizlet.features.achievements.viewmodel.c) objE;
            } else {
                c0814p.Q();
                i2 = i3 & (-897);
                function12 = function1;
                obj = cVar;
            }
            c0814p.q();
            com.quizlet.features.achievements.viewmodel.b bVar = (com.quizlet.features.achievements.viewmodel.b) obj;
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(bVar.g, c0814p);
            d0 d0Var = bVar.i;
            c0814p.X(-2041288898);
            boolean z = (i2 & 14) == 4;
            Object objI2 = c0814p.I();
            if (z || objI2 == obj3) {
                objI2 = new D(null, function0, function12);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            J j = (J) c0814p.j(g.a);
            Object obj4 = B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(obj4) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI3 = c0814p.I();
            if (zF || objI3 == obj3) {
                objI3 = new C(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            h hVar = (h) AbstractC4178x.k(unit, (Function2) objI3, c0814p, false, interfaceC0773a0M);
            c0814p.X(-2041280234);
            boolean zH = c0814p.h(obj);
            Object objI4 = c0814p.I();
            if (zH || objI4 == obj3) {
                Object fVar = new com.quizlet.explanations.textbook.ui.f(1, obj, com.quizlet.features.achievements.viewmodel.c.class, "onEvent", "onEvent(Lcom/quizlet/features/achievements/data/AchievementsEvent;)V", 0, 4);
                c0814p.i0(fVar);
                objI4 = fVar;
            }
            c0814p.p(false);
            b(hVar, (Function1) ((kotlin.reflect.f) objI4), c0814p, 0);
            function13 = function12;
            obj2 = obj;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new e(function0, function13, obj2, i, 15);
        }
    }

    public static final void b(h hVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        int i2 = 0;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1635723824);
        if ((((c0814p2.f(hVar) ? 4 : 2) | i | (c0814p2.h(function1) ? 32 : 16)) & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            q qVarG = N.G(n.b, "AchievementsScreen");
            d dVarE = androidx.compose.runtime.internal.e.e(1283206292, new E(i2, function1), c0814p2);
            long jG = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g();
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(qVarG, dVarE, null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(692332767, new m(5, hVar, function1), c0814p2), c0814p, 805306422, 188);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(hVar, function1, i, 11);
        }
    }

    public static final void c(int i, InterfaceC0806l interfaceC0806l, n nVar, Function0 function0) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1229789695);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i | 48;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            n nVar2 = n.b;
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            String strD = AbstractC3106b5.d(c0814p, R.string.nav2_models_list_title_achievements);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            AbstractC3691o6.c(nVar2, strD, jG, 0L, com.quizlet.ui.resources.icons.d.m(c0814p), function0, null, null, c0814p, 6 | ((i2 << 15) & 458752), 200);
            nVar = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new A(function0, nVar, i, 0);
        }
    }

    public static final io.reactivex.rxjava3.core.g d(Object obj) {
        if (obj != null) {
            return io.reactivex.rxjava3.core.g.c(obj);
        }
        io.reactivex.rxjava3.internal.operators.maybe.f fVar = io.reactivex.rxjava3.internal.operators.maybe.f.a;
        Intrinsics.checkNotNullExpressionValue(fVar, "empty(...)");
        return fVar;
    }

    public static boolean e(C0132i c0132i) {
        Boolean bool;
        try {
            CameraCharacteristics.Key key = CameraCharacteristics.FLASH_INFO_AVAILABLE;
            c0132i.getClass();
            bool = (Boolean) ((k) c0132i.b).a(CameraCharacteristics.FLASH_INFO_AVAILABLE);
        } catch (BufferUnderflowException e) {
            if (androidx.camera.camera2.internal.compat.quirk.b.a.b(FlashAvailabilityBufferUnderflowQuirk.class) != null) {
                String.format("Device is known to throw an exception while checking flash availability. Flash is not available. [Manufacturer: %s, Model: %s, API Level: %d].", Build.MANUFACTURER, Build.MODEL, Integer.valueOf(Build.VERSION.SDK_INT));
                AbstractC3053s1.f(3, "FlashAvailability");
            } else {
                AbstractC3053s1.d("FlashAvailability", String.format("Exception thrown while checking for flash availability on device not known to throw exceptions during this check. Please file an issue at https://issuetracker.google.com/issues/new?component=618491&template=1257717 with this error message [Manufacturer: %s, Model: %s, API Level: %d].\nFlash is not available.", Build.MANUFACTURER, Build.MODEL, Integer.valueOf(Build.VERSION.SDK_INT)), e);
            }
            bool = Boolean.FALSE;
        }
        if (bool == null) {
            AbstractC3053s1.h("FlashAvailability", "Characteristics did not contain key FLASH_INFO_AVAILABLE. Flash is not available.");
        }
        if (bool != null) {
            return bool.booleanValue();
        }
        return false;
    }

    public static synchronized boolean f(Context context) {
        Boolean bool;
        Context applicationContext = context.getApplicationContext();
        Context context2 = a;
        if (context2 != null && (bool = b) != null && context2 == applicationContext) {
            return bool.booleanValue();
        }
        b = null;
        Boolean boolValueOf = Boolean.valueOf(applicationContext.getPackageManager().isInstantApp());
        b = boolValueOf;
        a = applicationContext;
        return boolValueOf.booleanValue();
    }
}
