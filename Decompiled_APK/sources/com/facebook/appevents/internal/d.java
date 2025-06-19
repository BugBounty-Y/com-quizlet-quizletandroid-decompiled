package com.facebook.appevents.internal;

import android.app.Activity;
import android.content.Context;
import android.hardware.camera2.CameraCharacteristics;
import android.os.Build;
import android.view.View;
import android.view.Window;
import androidx.camera.camera2.internal.compat.CameraAccessExceptionCompat;
import androidx.camera.core.CameraUnavailableException;
import androidx.camera.core.InitializationException;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.E0;
import androidx.compose.foundation.layout.G0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.compose.ui.platform.N;
import androidx.compose.ui.q;
import androidx.compose.ui.text.L;
import com.airbnb.lottie.compose.o;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.google.android.gms.internal.measurement.AbstractC3058t1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3515q;
import com.google.android.gms.internal.mlkit_vision_common.r;
import com.quizlet.data.model.C4114c;
import com.quizlet.themes.w;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public abstract class d {
    public static final void a(C4114c badge, com.quizlet.features.achievements.achievement.g theme, n nVar, InterfaceC0806l interfaceC0806l, int i) {
        n nVar2;
        Intrinsics.checkNotNullParameter(badge, "badge");
        Intrinsics.checkNotNullParameter(theme, "theme");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-416502376);
        int i2 = i | (c0814p.h(badge) ? 4 : 2) | (c0814p.f(theme) ? 32 : 16) | 384;
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            n nVar3 = n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            q qVarF = AbstractC0460p.f(nVar3, F.c(com.quizlet.themes.extensions.a.a((Context) c0814p.j(AndroidCompositionLocals_androidKt.b), theme.a)), F.a);
            K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC = androidx.compose.ui.a.c(c0814p, qVarF);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, kE, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            AbstractC3515q.a((com.airbnb.lottie.h) r.d(new o(theme.c), c0814p).getValue(), N.G(nVar3, "achievementsNotificationImage"), 0, null, null, c0814p, 48, 0, 4194300);
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            q qVarU = AbstractC0382e.u(nVar3, f);
            G0 g0B = E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarU);
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
            C0776c.E(c0814p, qVarC2, c0912h4);
            AbstractC3058t1.a(badge, null, com.quizlet.themes.m.t, null, c0814p, i2 & 14, 10);
            B bA = A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
            q qVarC3 = androidx.compose.ui.a.c(c0814p, nVar3);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L3, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            androidx.compose.runtime.B b = w.a;
            L l = ((com.quizlet.themes.f) c0814p.j(b)).k;
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.q();
            q qVarY = AbstractC0382e.y(nVar3, f2, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, 10);
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            Q4.b(badge.d, qVarY, ((com.quizlet.themes.b) c0814p.j(b2)).v(), 0L, null, 0L, null, 0L, 0, false, 2, 0, null, l, c0814p, 0, 3072, 57336);
            L l2 = ((com.quizlet.themes.f) c0814p.j(b)).e;
            mVar.s();
            mVar.q();
            mVar.u();
            Q4.b(badge.e, AbstractC0382e.y(nVar3, f2, com.quizlet.ui.resources.designsystem.generated.j.g, f, DefinitionKt.NO_Float_VALUE, 8), ((com.quizlet.themes.b) c0814p.j(b2)).v(), 0L, null, 0L, null, 0L, 0, false, 2, 0, null, l2, c0814p, 0, 3072, 57336);
            c0814p = c0814p;
            androidx.compose.ui.node.B.s(c0814p, true, true, true);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 14, badge, theme, nVar2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(kotlin.jvm.functions.Function1 r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            boolean r0 = r5 instanceof com.quizlet.qutils.coroutines.e
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.qutils.coroutines.e r0 = (com.quizlet.qutils.coroutines.e) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.k = r1
            goto L18
        L13:
            com.quizlet.qutils.coroutines.e r0 = new com.quizlet.qutils.coroutines.e
            r0.<init>(r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.k
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)     // Catch: java.lang.Throwable -> L40
            goto L3d
        L27:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlin.p r5 = kotlin.r.b     // Catch: java.lang.Throwable -> L40
            r0.k = r3     // Catch: java.lang.Throwable -> L40
            java.lang.Object r5 = r4.invoke(r0)     // Catch: java.lang.Throwable -> L40
            if (r5 != r1) goto L3d
            return r1
        L3d:
            kotlin.p r4 = kotlin.r.b     // Catch: java.lang.Throwable -> L40
            return r5
        L40:
            r4 = move-exception
            kotlin.p r5 = kotlin.r.b
            kotlin.q r4 = androidx.glance.appwidget.protobuf.Z.b(r4)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.internal.d.b(kotlin.jvm.functions.Function1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final View c(Activity activity) {
        if (com.facebook.internal.instrument.crashshield.a.b(d.class) || activity == null) {
            return null;
        }
        try {
            Window window = activity.getWindow();
            if (window == null) {
                return null;
            }
            return window.getDecorView().getRootView();
        } catch (Exception unused) {
            return null;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(d.class, th);
            return null;
        }
    }

    public static boolean d(androidx.camera.camera2.internal.compat.q qVar, String str) throws InitializationException {
        if ("robolectric".equals(Build.FINGERPRINT)) {
            return true;
        }
        try {
            int[] iArr = (int[]) qVar.b(str).a(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES);
            if (iArr != null) {
                for (int i : iArr) {
                    if (i == 0) {
                        return true;
                    }
                }
            }
            return false;
        } catch (CameraAccessExceptionCompat e) {
            throw new InitializationException(new CameraUnavailableException(e));
        }
    }

    public static final boolean e() {
        String FINGERPRINT = Build.FINGERPRINT;
        Intrinsics.checkNotNullExpressionValue(FINGERPRINT, "FINGERPRINT");
        if (D.r(FINGERPRINT, "generic", false)) {
            return true;
        }
        Intrinsics.checkNotNullExpressionValue(FINGERPRINT, "FINGERPRINT");
        if (D.r(FINGERPRINT, DtbDeviceDataRetriever.ORIENTATION_UNKNOWN, false)) {
            return true;
        }
        String MODEL = Build.MODEL;
        Intrinsics.checkNotNullExpressionValue(MODEL, "MODEL");
        if (StringsKt.G(MODEL, "google_sdk", false)) {
            return true;
        }
        Intrinsics.checkNotNullExpressionValue(MODEL, "MODEL");
        if (StringsKt.G(MODEL, "Emulator", false)) {
            return true;
        }
        Intrinsics.checkNotNullExpressionValue(MODEL, "MODEL");
        if (StringsKt.G(MODEL, "Android SDK built for x86", false)) {
            return true;
        }
        String MANUFACTURER = Build.MANUFACTURER;
        Intrinsics.checkNotNullExpressionValue(MANUFACTURER, "MANUFACTURER");
        if (StringsKt.G(MANUFACTURER, "Genymotion", false)) {
            return true;
        }
        String BRAND = Build.BRAND;
        Intrinsics.checkNotNullExpressionValue(BRAND, "BRAND");
        if (D.r(BRAND, "generic", false)) {
            String DEVICE = Build.DEVICE;
            Intrinsics.checkNotNullExpressionValue(DEVICE, "DEVICE");
            if (D.r(DEVICE, "generic", false)) {
                return true;
            }
        }
        return "google_sdk".equals(Build.PRODUCT);
    }
}
