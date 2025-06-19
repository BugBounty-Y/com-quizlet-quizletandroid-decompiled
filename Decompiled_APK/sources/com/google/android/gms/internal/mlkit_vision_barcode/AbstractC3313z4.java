package com.google.android.gms.internal.mlkit_vision_barcode;

import android.app.Activity;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Point;
import android.graphics.Rect;
import android.os.Build;
import android.util.Log;
import android.view.Display;
import android.view.WindowManager;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.HorizontalAlignElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.InterfaceC1261w;
import com.amazon.device.ads.DtbConstants;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3586b5;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.assembly.compose.buttons.C4088m;
import com.quizlet.assembly.compose.buttons.C4090o;
import com.quizlet.assembly.compose.buttons.C4097w;
import com.quizlet.assembly.compose.buttons.InterfaceC4092q;
import com.quizlet.features.folders.composables.AbstractC4253i;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.z4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3313z4 {
    public static final /* synthetic */ int a = 0;

    public static final void a(com.quizlet.features.folders.changetags.data.f state, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        boolean z;
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1845123803);
        int i2 = i | (c0814p.h(state) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            d(null, c0814p, 0);
            c0814p.X(-1108714221);
            if (state.c.d.isEmpty()) {
                z = true;
            } else {
                androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "subfolder_flow_row");
                com.quizlet.themes.m.g.q();
                androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarG, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
                c0814p.X(-1108703706);
                boolean z2 = (i2 & 896) == 256;
                Object objI = c0814p.I();
                if (z2 || objI == v) {
                    objI = new androidx.navigation.compose.B(8, function1);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                AbstractC3179j6.a(state.c, state.b, (Function1) objI, qVarY, c0814p, 8);
                z = true;
                androidx.compose.animation.E.f(state.a, null, AbstractC4253i.a, AbstractC4253i.b, null, androidx.compose.runtime.internal.e.e(-1393847858, new com.quizlet.assembly.compose.input.m(9, state, function1), c0814p), c0814p, 1600518, 18);
            }
            c0814p.p(false);
            c0814p.p(z);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 18, state, qVar, function1);
        }
    }

    public static final void b(com.quizlet.features.folders.changetags.data.f state, androidx.compose.ui.q qVar, Function0 function0, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0912h c0912h;
        C0814p c0814p;
        boolean z;
        C0912h c0912h2;
        C0912h c0912h3;
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-752935173);
        int i2 = i | (c0814p2.h(state) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.h(function0) ? 256 : 128) | (c0814p2.h(function1) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0912h c0912h4 = C0914j.f;
            C0776c.E(c0814p2, bA, c0912h4);
            C0912h c0912h5 = C0914j.e;
            C0776c.E(c0814p2, interfaceC0803j0L, c0912h5);
            C0912h c0912h6 = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h6);
            }
            C0912h c0912h7 = C0914j.d;
            C0776c.E(c0814p2, qVarC, c0912h7);
            d(null, c0814p2, 0);
            c0814p2.X(-940948483);
            if (state.c.d.isEmpty()) {
                c0912h = c0912h4;
                c0814p = c0814p2;
                z = false;
                c0912h2 = c0912h5;
                c0912h3 = c0912h6;
            } else {
                androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "subfolder_flow_row");
                com.quizlet.themes.m.g.p();
                androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarG, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
                c0814p2.X(-940937316);
                boolean z2 = (i2 & 7168) == 2048;
                Object objI = c0814p2.I();
                if (z2 || objI == v) {
                    objI = new androidx.navigation.compose.B(9, function1);
                    c0814p2.i0(objI);
                }
                c0814p2.p(false);
                c0912h = c0912h4;
                c0814p = c0814p2;
                c0912h2 = c0912h5;
                c0912h3 = c0912h6;
                z = false;
                AbstractC3179j6.a(state.c, state.b, (Function1) objI, qVarY, c0814p, 8);
            }
            c0814p.p(z);
            HorizontalAlignElement horizontalAlignElement = new HorizontalAlignElement(androidx.compose.ui.b.o);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.t();
            androidx.compose.ui.q qVarY2 = AbstractC0382e.y(horizontalAlignElement, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.k, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            mVar.s();
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h), androidx.compose.ui.b.j, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarY2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h7);
            C0814p c0814p3 = c0814p;
            AbstractC3586b5.a(AbstractC3106b5.d(c0814p, R.string.cancel), null, function0, false, C4076a.m, C4097w.a, null, null, null, c0814p3, i2 & 896, 970);
            String strD = AbstractC3106b5.d(c0814p3, R.string.done);
            com.quizlet.assembly.compose.buttons.r rVar = com.quizlet.assembly.compose.buttons.r.a;
            c0814p3.X(-758936252);
            InterfaceC4092q c4088m = state.d ? new C4088m() : C4090o.a;
            c0814p3.p(false);
            c0814p3.X(707506081);
            boolean z3 = (i2 & 7168) == 2048;
            Object objI2 = c0814p3.I();
            if (z3 || objI2 == v) {
                objI2 = new com.quizlet.facebook.a(10, function1);
                c0814p3.i0(objI2);
            }
            c0814p3.p(false);
            com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(strD, null, (Function0) objI2, state.a, null, rVar, c4088m, null, null, false, c0814p3, 0, 914);
            c0814p2 = c0814p3;
            c0814p2.p(true);
            c0814p2.p(true);
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i((Object) state, (Object) qVar, function0, (Object) function1, i, 4);
        }
    }

    public static final void c(com.quizlet.assembly.compose.modals.x modalState, androidx.compose.ui.n nVar, Function1 function1, com.quizlet.features.folders.changetags.viewmodel.e eVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        int i3;
        com.quizlet.features.folders.changetags.viewmodel.e eVar2;
        androidx.compose.ui.n nVar2;
        com.quizlet.features.folders.changetags.viewmodel.e eVar3;
        com.quizlet.features.folders.changetags.viewmodel.e eVar4;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1446285930);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(modalState) : c0814p.h(modalState) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i4 = i2 | 48;
        if ((i & 384) == 0) {
            i4 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i4 |= 1024;
        }
        if ((i4 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
            eVar4 = eVar;
        } else {
            c0814p.S();
            int i5 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i5 == 0 || c0814p.w()) {
                androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                Object objE = AbstractC3417z1.e(com.quizlet.features.folders.changetags.viewmodel.d.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i3 = i4 & (-7169);
                eVar2 = (com.quizlet.features.folders.changetags.viewmodel.e) objE;
                nVar2 = nVar3;
            } else {
                c0814p.Q();
                nVar2 = nVar;
                i3 = i4 & (-7169);
                eVar2 = eVar;
            }
            c0814p.q();
            com.quizlet.features.folders.changetags.viewmodel.d dVar = (com.quizlet.features.folders.changetags.viewmodel.d) eVar2;
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(dVar.h, c0814p);
            c0814p.X(-1367725320);
            boolean zH = c0814p.h(eVar2);
            boolean z = true;
            Object objI = c0814p.I();
            if (zH || objI == v) {
                eVar3 = eVar2;
                objI = new com.quizlet.explanations.textbook.ui.f(1, eVar3, com.quizlet.features.folders.changetags.viewmodel.e.class, "onChangeTagsEvent", "onChangeTagsEvent(Lcom/quizlet/features/folders/changetags/data/ChangeTagsEvent;)V", 0, 19);
                c0814p.i0(objI);
            } else {
                eVar3 = eVar2;
            }
            kotlin.reflect.f fVar = (kotlin.reflect.f) objI;
            c0814p.p(false);
            kotlinx.coroutines.flow.d0 d0Var = dVar.g;
            c0814p.X(-1367722864);
            int i6 = i3 & 14;
            boolean z2 = ((i3 & 896) == 256) | (i6 == 4 || ((i3 & 8) != 0 && c0814p.h(modalState)));
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new com.quizlet.features.folders.changetags.composables.d(modalState, null, function1);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI3 = c0814p.I();
            if (zF || objI3 == v) {
                objI3 = new com.quizlet.features.folders.changetags.composables.c(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI3);
            c0814p.p(false);
            Boolean boolValueOf = Boolean.valueOf(modalState.b());
            c0814p.X(-1367718231);
            if (i6 != 4 && ((i3 & 8) == 0 || !c0814p.h(modalState))) {
                z = false;
            }
            boolean zF2 = z | c0814p.f(fVar);
            Object objI4 = c0814p.I();
            if (zF2 || objI4 == v) {
                objI4 = new com.quizlet.features.folders.changetags.composables.e(modalState, fVar, null);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            C0776c.f(c0814p, boolValueOf, (Function2) objI4);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-135495884, new androidx.navigation.compose.o(16, fVar, interfaceC0773a0M), c0814p);
            androidx.compose.runtime.internal.d dVarE2 = androidx.compose.runtime.internal.e.e(1388266738, new com.quizlet.assembly.compose.menu.l(modalState, fVar, interfaceC0773a0M, 7), c0814p);
            c0814p.X(-1367661634);
            boolean zF3 = c0814p.f(fVar);
            Object objI5 = c0814p.I();
            if (zF3 || objI5 == v) {
                objI5 = new com.quizlet.featuregate.growthbook.a(fVar, 4);
                c0814p.i0(objI5);
            }
            c0814p.p(false);
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.a(modalState, dVarE, nVar2, dVarE2, null, null, null, false, (Function0) objI5, c0814p, 3128 | i6 | ((i3 << 3) & 896), 240);
            c0814p = c0814p;
            eVar4 = eVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i((Object) modalState, (Object) nVar2, function1, (Object) eVar4, i, 9);
        }
    }

    public static final void d(androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1028007788);
        if (((i | 6) & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            nVar2 = androidx.compose.ui.n.b;
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, R.string.change_tags_title), nVar2, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).e, c0814p, 48, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.changetags.composables.a(nVar2, i, 0);
        }
    }

    public static final androidx.compose.material3.windowsizeclass.b e(Activity activity, InterfaceC0806l interfaceC0806l) {
        Rect rectA;
        androidx.core.view.D0 _windowInsetsCompat;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.j(AndroidCompositionLocals_androidKt.a);
        androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
        androidx.window.layout.b.a.getClass();
        androidx.window.layout.c it2 = androidx.window.layout.c.b;
        Intrinsics.checkNotNullParameter(it2, "it");
        Intrinsics.checkNotNullParameter(activity, "activity");
        int i = Build.VERSION.SDK_INT;
        if (i >= 30) {
            Intrinsics.checkNotNullParameter(activity, "context");
            rectA = ((WindowManager) activity.getSystemService(WindowManager.class)).getCurrentWindowMetrics().getBounds();
            Intrinsics.checkNotNullExpressionValue(rectA, "wm.currentWindowMetrics.bounds");
        } else if (i >= 29) {
            String str = androidx.window.layout.c.c;
            Intrinsics.checkNotNullParameter(activity, "activity");
            Configuration configuration = activity.getResources().getConfiguration();
            try {
                Field declaredField = Configuration.class.getDeclaredField("windowConfiguration");
                declaredField.setAccessible(true);
                Object obj = declaredField.get(configuration);
                Object objInvoke = obj.getClass().getDeclaredMethod("getBounds", null).invoke(obj, null);
                Intrinsics.e(objInvoke, "null cannot be cast to non-null type android.graphics.Rect");
                rectA = new Rect((Rect) objInvoke);
            } catch (IllegalAccessException e) {
                Log.w(str, e);
                rectA = androidx.window.layout.c.a(activity);
            } catch (NoSuchFieldException e2) {
                Log.w(str, e2);
                rectA = androidx.window.layout.c.a(activity);
            } catch (NoSuchMethodException e3) {
                Log.w(str, e3);
                rectA = androidx.window.layout.c.a(activity);
            } catch (InvocationTargetException e4) {
                Log.w(str, e4);
                rectA = androidx.window.layout.c.a(activity);
            }
        } else if (i >= 28) {
            rectA = androidx.window.layout.c.a(activity);
        } else {
            Intrinsics.checkNotNullParameter(activity, "activity");
            Rect rect = new Rect();
            Display display = activity.getWindowManager().getDefaultDisplay();
            display.getRectSize(rect);
            Intrinsics.checkNotNullParameter(activity, "activity");
            if (!activity.isInMultiWindowMode()) {
                Intrinsics.checkNotNullExpressionValue(display, "defaultDisplay");
                Intrinsics.checkNotNullParameter(display, "display");
                Point point = new Point();
                display.getRealSize(point);
                Resources resources = activity.getResources();
                int identifier = resources.getIdentifier("navigation_bar_height", "dimen", DtbConstants.NATIVE_OS_NAME);
                int dimensionPixelSize = identifier > 0 ? resources.getDimensionPixelSize(identifier) : 0;
                int i2 = rect.bottom + dimensionPixelSize;
                if (i2 == point.y) {
                    rect.bottom = i2;
                } else {
                    int i3 = rect.right + dimensionPixelSize;
                    if (i3 == point.x) {
                        rect.right = i3;
                    }
                }
            }
            rectA = rect;
        }
        int i4 = Build.VERSION.SDK_INT;
        if (i4 >= 30) {
            Intrinsics.checkNotNullParameter(activity, "context");
            if (i4 < 30) {
                throw new Exception("Incompatible SDK version");
            }
            _windowInsetsCompat = androidx.window.layout.util.a.a.a(activity);
        } else {
            _windowInsetsCompat = (i4 >= 34 ? new androidx.core.view.r0() : i4 >= 30 ? new androidx.core.view.q0() : i4 >= 29 ? new androidx.core.view.p0() : new androidx.core.view.n0()).b();
            Intrinsics.checkNotNullExpressionValue(_windowInsetsCompat, "{\n            WindowInse…ilder().build()\n        }");
        }
        androidx.window.core.a _bounds = new androidx.window.core.a(rectA);
        Intrinsics.checkNotNullParameter(_bounds, "_bounds");
        Intrinsics.checkNotNullParameter(_windowInsetsCompat, "_windowInsetsCompat");
        androidx.compose.ui.geometry.c cVarC = androidx.compose.ui.graphics.F.C(new Rect(_bounds.a, _bounds.b, _bounds.c, _bounds.d));
        return com.quizlet.shared.usecase.folderstudymaterials.a.m(bVar.s(T4.a(cVarC.e(), cVarC.d())));
    }
}
