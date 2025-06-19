package com.facebook.appevents;

import android.graphics.ColorFilter;
import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import android.view.View;
import androidx.compose.animation.core.J0;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.foundation.layout.E0;
import androidx.compose.foundation.layout.G0;
import androidx.compose.foundation.layout.K0;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.V0;
import androidx.compose.ui.text.L;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import androidx.navigation.U;
import androidx.navigation.compose.C1278k;
import com.google.android.gms.internal.mlkit_vision_barcode.A5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3137f0;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.R4;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.features.achievements.ui.composables.C4218e;
import com.quizlet.features.achievements.ui.composables.C4219f;
import com.quizlet.features.achievements.ui.composables.C4220g;
import com.quizlet.features.achievements.ui.composables.C4221h;
import com.quizlet.features.achievements.ui.composables.C4222i;
import com.quizlet.features.achievements.ui.composables.C4223j;
import com.quizlet.features.achievements.ui.composables.C4224k;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import io.reactivex.rxjava3.internal.operators.observable.m0;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class m {
    public static final void a(androidx.camera.core.impl.utils.e uiState, Function0 onClick, androidx.compose.ui.q qVar, int i, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2018402148);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.f(uiState) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.h(onClick) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p.f(qVar) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p.d(i) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i2 & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            if (uiState instanceof com.quizlet.features.achievements.achievement.h) {
                c0814p.X(-1574811623);
                com.quizlet.features.achievements.achievement.h hVar = (com.quizlet.features.achievements.achievement.h) uiState;
                b(i, hVar.e, hVar.b, hVar.c, hVar.d, qVar, onClick, c0814p, (458752 & (i3 << 9)) | ((i3 >> 9) & 14) | ((i3 << 15) & 3670016));
                c0814p = c0814p;
                c0814p.p(false);
            } else if (uiState instanceof com.quizlet.features.achievements.achievement.i) {
                c0814p.X(-1574167647);
                com.quizlet.features.achievements.achievement.i iVar = (com.quizlet.features.achievements.achievement.i) uiState;
                f(i, iVar.f, iVar.c, iVar.d, iVar.e, qVar, Integer.valueOf(iVar.b), onClick, c0814p, (458752 & (i3 << 9)) | ((i3 >> 9) & 14) | ((i3 << 18) & 29360128));
                c0814p = c0814p;
                c0814p.p(false);
            } else {
                if (!(uiState instanceof com.quizlet.features.achievements.achievement.j)) {
                    throw Z.j(-1574813016, c0814p, false);
                }
                c0814p.X(-1574787757);
                com.quizlet.features.achievements.achievement.j jVar = (com.quizlet.features.achievements.achievement.j) uiState;
                c(i, jVar.b, jVar.c, jVar.d, qVar, onClick, c0814p, ((i3 >> 9) & 14) | (57344 & (i3 << 6)) | ((i3 << 12) & 458752));
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4218e(i, i2, 0, qVar, (Object) uiState, (Object) onClick);
        }
    }

    public static final void b(int i, kotlinx.collections.immutable.b bVar, String str, String str2, String str3, androidx.compose.ui.q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        int i4;
        String str4;
        String str5;
        String str6;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(543227802);
        if ((i2 & 6) == 0) {
            i3 = i;
            i4 = (c0814p2.d(i3) ? 4 : 2) | i2;
        } else {
            i3 = i;
            i4 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 |= c0814p2.f(bVar) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            str4 = str;
            i4 |= c0814p2.f(str4) ? 256 : 128;
        } else {
            str4 = str;
        }
        if ((i2 & 3072) == 0) {
            str5 = str2;
            i4 |= c0814p2.f(str5) ? 2048 : 1024;
        } else {
            str5 = str2;
        }
        if ((i2 & 24576) == 0) {
            str6 = str3;
            i4 |= c0814p2.f(str6) ? 16384 : 8192;
        } else {
            str6 = str3;
        }
        if ((196608 & i2) == 0) {
            i4 |= c0814p2.f(qVar) ? 131072 : 65536;
        }
        if ((1572864 & i2) == 0) {
            i4 |= c0814p2.h(function0) ? 1048576 : 524288;
        }
        int i5 = i4;
        if ((599187 & i5) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            String str7 = str6;
            c0814p = c0814p2;
            R4.a(qVar, null, 0L, 0L, 0L, function0, false, null, null, null, androidx.compose.runtime.internal.e.e(-65378604, new com.quizlet.assembly.compose.listitems.w(i3, str4, str5, str7, bVar), c0814p2), c0814p, ((i5 >> 15) & 14) | ((i5 >> 3) & 458752), 990);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.links.j(i, bVar, str, str2, str3, qVar, function0, i2);
        }
    }

    public static final void c(int i, String str, String str2, String str3, androidx.compose.ui.q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        Function0 function02;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-344338490);
        if ((i2 & 6) == 0) {
            i3 = (c0814p2.d(i) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p2.f(str) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p2.f(str2) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p2.f(str3) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i3 |= c0814p2.f(qVar) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            function02 = function0;
            i3 |= c0814p2.h(function02) ? 131072 : 65536;
        } else {
            function02 = function0;
        }
        if ((74899 & i3) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            R4.a(qVar, null, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).V, 0L, 0L, function02, false, null, null, null, androidx.compose.runtime.internal.e.e(-1905455412, new C4223j(str, i, str2, str3), c0814p2), c0814p, ((i3 >> 12) & 14) | (i3 & 458752), 986);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.h(i, str, str2, str3, qVar, function0, i2);
        }
    }

    public static final void d(String str, String str2, String str3, InterfaceC0806l interfaceC0806l, int i) {
        ColorFilter porterDuffColorFilter;
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1778074620);
        int i3 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.f(str2) ? 32 : 16) | (c0814p.f(str3) ? 256 : 128);
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.i iVar = androidx.compose.ui.b.i;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            K kE = AbstractC0409s.e(iVar, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            C0418x c0418x = C0418x.a;
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.no_streak_background_compat, c0814p, 0);
            androidx.compose.ui.i iVar2 = androidx.compose.ui.b.f;
            long j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).W;
            if (Build.VERSION.SDK_INT >= 29) {
                porterDuffColorFilter = C0854n.a.a(j, 5);
                i2 = 5;
            } else {
                porterDuffColorFilter = new PorterDuffColorFilter(F.A(j), F.E(5));
                i2 = 5;
            }
            AbstractC0460p.c(bVarA, null, c0418x.b(nVar), iVar2, null, DefinitionKt.NO_Float_VALUE, new C0853m(j, i2, porterDuffColorFilter), c0814p, 3120, 48);
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.p();
            float f = com.quizlet.ui.resources.designsystem.generated.j.j;
            androidx.compose.ui.q qVarU = AbstractC0382e.u(nVar, f);
            B bA = A.a(AbstractC0398m.c, gVar, c0814p, 48);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarU);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            j(str3, androidx.compose.ui.draw.g.i(nVar, 10.0f), null, null, c0814p, ((i3 >> 6) & 14) | 48, 12);
            mVar.p();
            k(i3 & 14, 4, 0L, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), str);
            mVar.u();
            i(str2, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), new androidx.compose.ui.text.style.i(3), 0L, c0814p, (i3 >> 3) & 14, 8);
            c0814p = c0814p;
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4220g(str, i, str2, str3, 0);
        }
    }

    public static final void e(String str, String str2, String str3, InterfaceC0806l interfaceC0806l, int i) {
        ColorFilter porterDuffColorFilter;
        C0912h c0912h;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(520361711);
        int i2 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.f(str2) ? 32 : 16) | (c0814p.f(str3) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.i iVar = androidx.compose.ui.b.f;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarF = K0.f(nVar, DefinitionKt.NO_Float_VALUE, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED, 1);
            K kE = AbstractC0409s.e(iVar, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarF);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h2 = C0914j.f;
            C0776c.E(c0814p, kE, c0912h2);
            C0912h c0912h3 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h3);
            C0912h c0912h4 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h4);
            }
            C0912h c0912h5 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h5);
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.no_streak_background_large, c0814p, 0);
            long j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).W;
            int i4 = 5;
            if (Build.VERSION.SDK_INT >= 29) {
                porterDuffColorFilter = C0854n.a.a(j, 5);
            } else {
                porterDuffColorFilter = new PorterDuffColorFilter(F.A(j), F.E(5));
                i4 = 5;
            }
            AbstractC0460p.c(bVarA, null, null, null, null, DefinitionKt.NO_Float_VALUE, new C0853m(j, i4, porterDuffColorFilter), c0814p, 48, 60);
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.t();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(nVar, com.quizlet.ui.resources.designsystem.generated.j.k, DefinitionKt.NO_Float_VALUE, 2);
            G0 g0B = E0.b(AbstractC0398m.a, hVar, c0814p, 48);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarW);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h2);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h3);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                c0912h = c0912h4;
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            } else {
                c0912h = c0912h4;
            }
            C0776c.E(c0814p, qVarC2, c0912h5);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true);
            B bA = A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i6 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, layoutWeightElement);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h2);
            C0776c.E(c0814p, interfaceC0803j0L3, c0912h3);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h);
            }
            C0776c.E(c0814p, qVarC3, c0912h5);
            k(i2 & 14, 6, 0L, c0814p, null, str);
            mVar.u();
            i(str2, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), null, 0L, c0814p, (i2 >> 3) & 14, 12);
            c0814p = c0814p;
            c0814p.p(true);
            androidx.compose.ui.q qVarK = K0.k(androidx.compose.ui.draw.g.i(nVar, 10.0f), ((com.quizlet.themes.j) c0814p.j(com.quizlet.themes.l.a)).b());
            mVar.p();
            j(str3, AbstractC0382e.y(qVarK, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), null, null, c0814p, (i2 >> 6) & 14, 12);
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4220g(str, i, str2, str3, 1);
        }
    }

    public static final void f(int i, kotlinx.collections.immutable.b bVar, String str, String str2, String str3, androidx.compose.ui.q qVar, Integer num, Function0 function0, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        int i4;
        String str4;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1780050094);
        if ((i2 & 6) == 0) {
            i3 = i;
            i4 = (c0814p2.d(i3) ? 4 : 2) | i2;
        } else {
            i3 = i;
            i4 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 |= c0814p2.f(bVar) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            str4 = str;
            i4 |= c0814p2.f(str4) ? 256 : 128;
        } else {
            str4 = str;
        }
        if ((i2 & 3072) == 0) {
            i4 |= c0814p2.f(str2) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i4 |= c0814p2.f(str3) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            i4 |= c0814p2.f(qVar) ? 131072 : 65536;
        }
        if ((1572864 & i2) == 0) {
            i4 |= c0814p2.f(num) ? 1048576 : 524288;
        }
        if ((12582912 & i2) == 0) {
            i4 |= c0814p2.h(function0) ? 8388608 : 4194304;
        }
        int i5 = i4;
        if ((4793491 & i5) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            R4.a(qVar, null, 0L, 0L, 0L, function0, false, null, null, null, androidx.compose.runtime.internal.e.e(2024397748, new C4224k(i3, bVar, str4, str2, str3, num), c0814p2), c0814p, ((i5 >> 15) & 14) | (458752 & (i5 >> 6)), 990);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4219f(i, bVar, str, str2, str3, qVar, num, function0, i2);
        }
    }

    public static final void g(kotlinx.collections.immutable.b bVar, String str, String str2, String str3, long j, Integer num, C0861v c0861v, int i, InterfaceC0806l interfaceC0806l, int i2, int i3) {
        Integer num2;
        int i4;
        C0861v c0861v2;
        int i5;
        int i6;
        int i7;
        Integer num3;
        int i8;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(204152602);
        int i9 = i2 | (c0814p.f(bVar) ? 4 : 2) | (c0814p.f(str) ? 32 : 16) | (c0814p.f(str2) ? 256 : 128) | (c0814p.f(str3) ? 2048 : 1024) | (c0814p.e(j) ? 16384 : 8192);
        int i10 = i3 & 32;
        if (i10 != 0) {
            i4 = i9 | 196608;
            num2 = num;
        } else {
            num2 = num;
            i4 = i9 | (c0814p.f(num2) ? 131072 : 65536);
        }
        int i11 = i3 & 64;
        if (i11 != 0) {
            i5 = i4 | 1572864;
            c0861v2 = c0861v;
        } else {
            c0861v2 = c0861v;
            i5 = i4 | (c0814p.f(c0861v2) ? 1048576 : 524288);
        }
        int i12 = i5 | 4194304;
        if ((4793491 & i12) == 4793490 && c0814p.x()) {
            c0814p.Q();
            i8 = i;
            num3 = num2;
        } else {
            c0814p.S();
            if ((i2 & 1) == 0 || c0814p.w()) {
                if (i10 != 0) {
                    num2 = null;
                }
                if (i11 != 0) {
                    c0861v2 = null;
                }
                i6 = i12 & (-29360129);
                i7 = 3;
            } else {
                c0814p.Q();
                i6 = i12 & (-29360129);
                i7 = i;
            }
            int i13 = i6;
            Integer num4 = num2;
            c0814p.q();
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = K0.c(nVar, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVarC, ((com.quizlet.themes.j) c0814p.j(com.quizlet.themes.l.a)).a());
            B bA = A.a(AbstractC0398m.c, gVar, c0814p, 48);
            int i14 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarU);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i14))) {
                android.support.v4.media.session.a.z(i14, c0814p, i14, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            int i15 = i13 >> 3;
            int i16 = i13 >> 6;
            k((i15 & 14) | (i16 & 896), 2, j, c0814p, null, str);
            L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            j(str3, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), num4, l, c0814p, (i13 >> 9) & 910, 0);
            mVar.q();
            i(str2, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), new androidx.compose.ui.text.style.i(i7), j, c0814p, (i16 & 14) | (i15 & 7168), 0);
            c0814p = c0814p;
            mVar.q();
            l(bVar, K0.q(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.v, 1), c0861v2, c0814p, (i13 & 14) | ((i13 >> 12) & 896));
            c0814p.p(true);
            num3 = num4;
            i8 = i7;
        }
        C0861v c0861v3 = c0861v2;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4221h(bVar, str, str2, str3, j, num3, c0861v3, i8, i2, i3, 0);
        }
    }

    public static final void h(kotlinx.collections.immutable.b bVar, String str, String str2, String str3, long j, Integer num, C0861v c0861v, int i, InterfaceC0806l interfaceC0806l, int i2, int i3) {
        Integer num2;
        int i4;
        C0861v c0861v2;
        int i5;
        int i6;
        int i7;
        C0861v c0861v3;
        int i8;
        Integer num3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1926551527);
        int i9 = i2 | (c0814p.f(bVar) ? 4 : 2) | (c0814p.f(str) ? 32 : 16) | (c0814p.f(str2) ? 256 : 128) | (c0814p.f(str3) ? 2048 : 1024) | (c0814p.e(j) ? 16384 : 8192);
        int i10 = i3 & 32;
        if (i10 != 0) {
            i4 = i9 | 196608;
            num2 = num;
        } else {
            num2 = num;
            i4 = i9 | (c0814p.f(num2) ? 131072 : 65536);
        }
        int i11 = i3 & 64;
        if (i11 != 0) {
            i5 = i4 | 1572864;
            c0861v2 = c0861v;
        } else {
            c0861v2 = c0861v;
            i5 = i4 | (c0814p.f(c0861v2) ? 1048576 : 524288);
        }
        int i12 = i5 | 4194304;
        if ((4793491 & i12) == 4793490 && c0814p.x()) {
            c0814p.Q();
            i8 = i;
            c0861v3 = c0861v2;
            num3 = num2;
        } else {
            c0814p.S();
            if ((i2 & 1) == 0 || c0814p.w()) {
                if (i10 != 0) {
                    num2 = null;
                }
                if (i11 != 0) {
                    c0861v2 = null;
                }
                i6 = i12 & (-29360129);
                i7 = 5;
            } else {
                c0814p.Q();
                i6 = i12 & (-29360129);
                i7 = i;
            }
            int i13 = i6;
            C0861v c0861v4 = c0861v2;
            c0814p.q();
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.ui.q qVarC = K0.c(AbstractC0382e.u(nVar, ((com.quizlet.themes.j) c0814p.j(com.quizlet.themes.l.a)).a()), 1.0f);
            C0380d c0380d = AbstractC0398m.a;
            Integer num4 = num2;
            G0 g0B = E0.b(c0380d, hVar, c0814p, 48);
            int i14 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, g0B, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i14))) {
                android.support.v4.media.session.a.z(i14, c0814p, i14, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC2, c0912h4);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f <= Float.MAX_VALUE ? 1.0f : Float.MAX_VALUE, true);
            G0 g0B2 = E0.b(c0380d, hVar, c0814p, 48);
            int i15 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, layoutWeightElement);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i15))) {
                android.support.v4.media.session.a.z(i15, c0814p, i15, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            j(str3, null, num4, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).e, c0814p, (i13 >> 9) & 910, 2);
            mVar.v();
            float f = com.quizlet.ui.resources.designsystem.generated.j.l;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14);
            B bA = A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i16 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
            androidx.compose.ui.q qVarC4 = androidx.compose.ui.a.c(c0814p, qVarY);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L3, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i16))) {
                android.support.v4.media.session.a.z(i16, c0814p, i16, c0912h3);
            }
            C0776c.E(c0814p, qVarC4, c0912h4);
            int i17 = i13 >> 3;
            int i18 = i13 >> 6;
            k((i17 & 14) | (i18 & 896), 2, j, c0814p, null, str);
            mVar.s();
            i(str2, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), new androidx.compose.ui.text.style.i(i7), j, c0814p, (i18 & 14) | (i17 & 7168), 0);
            c0814p = c0814p;
            c0814p.p(true);
            c0814p.p(true);
            mVar.v();
            l(bVar, K0.o(AbstractC0382e.y(nVar, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), com.quizlet.themes.m.u), c0861v4, c0814p, (i13 & 14) | ((i13 >> 12) & 896));
            c0814p.p(true);
            c0861v3 = c0861v4;
            i8 = i7;
            num3 = num4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4221h(bVar, str, str2, str3, j, num3, c0861v3, i8, i2, i3, 1);
        }
    }

    public static final void i(String str, androidx.compose.ui.q qVar, androidx.compose.ui.text.style.i iVar, long j, InterfaceC0806l interfaceC0806l, final int i, final int i2) {
        int i3;
        final String str2;
        final androidx.compose.ui.q qVar2;
        final androidx.compose.ui.text.style.i iVar2;
        final long j2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1001089209);
        if ((i & 6) == 0) {
            i3 = (c0814p.f(str) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.f(qVar) ? 32 : 16;
        }
        int i4 = i2 & 4;
        if (i4 != 0) {
            i3 |= 384;
        } else if ((i & 384) == 0) {
            i3 |= c0814p.f(iVar) ? 256 : 128;
        }
        int i5 = i2 & 8;
        if (i5 != 0) {
            i3 |= 3072;
        } else if ((i & 3072) == 0) {
            i3 |= c0814p.e(j) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            j2 = j;
            iVar2 = iVar;
            qVar2 = qVar;
            str2 = str;
        } else {
            if (i4 != 0) {
                iVar = null;
            }
            androidx.compose.ui.text.style.i iVar3 = iVar;
            if (i5 != 0) {
                j = C0861v.g;
            }
            long j3 = j;
            A5.f(str, qVar, iVar3, j3, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).o, c0814p, i3 & 8190);
            str2 = str;
            qVar2 = qVar;
            iVar2 = iVar3;
            j2 = j3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.achievements.ui.composables.c
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    String str3 = str2;
                    long j4 = j2;
                    com.facebook.appevents.m.i(str3, qVar2, iVar2, j4, (InterfaceC0806l) obj, iH, i2);
                    return Unit.a;
                }
            };
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0040  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0045  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x005b  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0078  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00a4  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00a9  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00ab  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00b0  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00de  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00e2  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00f5  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0103  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x0139  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0193  */
    /* JADX WARN: Removed duplicated region for block: B:85:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void j(java.lang.String r28, androidx.compose.ui.q r29, java.lang.Integer r30, androidx.compose.ui.text.L r31, androidx.compose.runtime.InterfaceC0806l r32, int r33, int r34) {
        /*
            Method dump skipped, instructions count: 416
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.m.j(java.lang.String, androidx.compose.ui.q, java.lang.Integer, androidx.compose.ui.text.L, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x003f  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0044  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x005c  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x006b  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x006d  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:49:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void k(final int r28, final int r29, long r30, androidx.compose.runtime.InterfaceC0806l r32, androidx.compose.ui.q r33, final java.lang.String r34) {
        /*
            r5 = r28
            r0 = r32
            androidx.compose.runtime.p r0 = (androidx.compose.runtime.C0814p) r0
            r1 = 1959711351(0x74ced277, float:1.310891E32)
            r0.Z(r1)
            r1 = r5 & 6
            if (r1 != 0) goto L1d
            r1 = r34
            boolean r2 = r0.f(r1)
            if (r2 == 0) goto L1a
            r2 = 4
            goto L1b
        L1a:
            r2 = 2
        L1b:
            r2 = r2 | r5
            goto L20
        L1d:
            r1 = r34
            r2 = r5
        L20:
            r3 = r29 & 2
            if (r3 == 0) goto L29
            r2 = r2 | 48
        L26:
            r4 = r33
            goto L3b
        L29:
            r4 = r5 & 48
            if (r4 != 0) goto L26
            r4 = r33
            boolean r6 = r0.f(r4)
            if (r6 == 0) goto L38
            r6 = 32
            goto L3a
        L38:
            r6 = 16
        L3a:
            r2 = r2 | r6
        L3b:
            r6 = r29 & 4
            if (r6 == 0) goto L44
            r2 = r2 | 384(0x180, float:5.38E-43)
        L41:
            r7 = r30
            goto L56
        L44:
            r7 = r5 & 384(0x180, float:5.38E-43)
            if (r7 != 0) goto L41
            r7 = r30
            boolean r9 = r0.e(r7)
            if (r9 == 0) goto L53
            r9 = 256(0x100, float:3.59E-43)
            goto L55
        L53:
            r9 = 128(0x80, float:1.8E-43)
        L55:
            r2 = r2 | r9
        L56:
            r9 = r2 & 147(0x93, float:2.06E-43)
            r10 = 146(0x92, float:2.05E-43)
            if (r9 != r10) goto L6b
            boolean r9 = r0.x()
            if (r9 != 0) goto L63
            goto L6b
        L63:
            r0.Q()
            r24 = r0
            r2 = r4
            r3 = r7
            goto La8
        L6b:
            if (r3 == 0) goto L70
            androidx.compose.ui.n r3 = androidx.compose.ui.n.b
            goto L71
        L70:
            r3 = r4
        L71:
            if (r6 == 0) goto L77
            long r6 = androidx.compose.ui.graphics.C0861v.g
            r8 = r6
            goto L78
        L77:
            r8 = r7
        L78:
            androidx.compose.runtime.B r4 = com.quizlet.themes.w.a
            java.lang.Object r4 = r0.j(r4)
            com.quizlet.themes.f r4 = (com.quizlet.themes.f) r4
            androidx.compose.ui.text.L r4 = r4.f
            r2 = r2 & 1022(0x3fe, float:1.432E-42)
            r21 = 0
            r22 = 0
            r10 = 0
            r12 = 0
            r13 = 0
            r15 = 0
            r16 = 0
            r18 = 0
            r19 = 0
            r20 = 0
            r26 = 0
            r27 = 65528(0xfff8, float:9.1824E-41)
            r24 = r0
            r6 = r1
            r25 = r2
            r7 = r3
            r23 = r4
            androidx.compose.material3.Q4.b(r6, r7, r8, r10, r12, r13, r15, r16, r18, r19, r20, r21, r22, r23, r24, r25, r26, r27)
            r2 = r7
            r3 = r8
        La8:
            androidx.compose.runtime.o0 r7 = r24.r()
            if (r7 == 0) goto Lb9
            com.quizlet.features.achievements.ui.composables.d r0 = new com.quizlet.features.achievements.ui.composables.d
            r6 = r29
            r1 = r34
            r0.<init>()
            r7.d = r0
        Lb9:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.m.k(int, int, long, androidx.compose.runtime.l, androidx.compose.ui.q, java.lang.String):void");
    }

    public static final void l(kotlinx.collections.immutable.b bVar, androidx.compose.ui.q qVar, C0861v c0861v, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        float f;
        int i3 = 0;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(490856610);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(bVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(c0861v) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            List listJ = kotlin.collections.B.j("S", "M", "T", "W", "T", "F", "S");
            B bA = A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
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
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            C0386g c0386g = AbstractC0398m.h;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC2 = K0.c(nVar, 1.0f);
            c0814p.X(-1780642172);
            Object objI = c0814p.I();
            V v = C0804k.a;
            if (objI == v) {
                objI = new C4222i(listJ, i3);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3137f0.b(qVarC2, null, null, c0386g, null, null, false, (Function1) objI, c0814p, 100687878, 238);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarY);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            C0418x c0418x = C0418x.a;
            c0814p.X(1716184393);
            if (c0861v == null) {
                f = 1.0f;
            } else {
                mVar.u();
                f = 1.0f;
                AbstractC0409s.a(AbstractC0460p.f(androidx.compose.ui.draw.g.c(c0418x.b(K0.c(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 1.0f)), androidx.compose.foundation.shape.e.a(100)), c0861v.a, F.a), c0814p, 0);
                Unit unit = Unit.a;
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarC4 = K0.c(nVar, f);
            c0814p.X(1716201103);
            boolean z = (i2 & 14) == 4;
            Object objI2 = c0814p.I();
            if (z || objI2 == v) {
                objI2 = new U(bVar, 26);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            AbstractC3137f0.b(qVarC4, null, null, c0386g, null, null, false, (Function1) objI2, c0814p, 24582, 238);
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 6, bVar, qVar, c0861v);
        }
    }

    public static final void m(com.quizlet.features.achievements.achievement.l lVar, InterfaceC0806l interfaceC0806l, int i) {
        long jE;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-332121452);
        if (((i | (c0814p.f(lVar) ? 4 : 2)) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.i iVar = androidx.compose.ui.b.h;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            float f = com.quizlet.themes.m.w;
            androidx.compose.ui.q qVarN = K0.n(nVar, f, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 12);
            K kE = AbstractC0409s.e(iVar, false);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarN);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(-2048560769);
            boolean z = lVar.c;
            C0854n c0854n = C0854n.a;
            if (z) {
                mVar.g();
                androidx.compose.ui.q qVarK = K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.h);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                androidx.compose.ui.graphics.painter.b bVarG = J0.G(c0814p);
                long jD = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).D();
                AbstractC0460p.c(bVarG, null, qVarK, null, null, DefinitionKt.NO_Float_VALUE, new C0853m(jD, 5, Build.VERSION.SDK_INT >= 29 ? c0854n.a(jD, 5) : new PorterDuffColorFilter(F.A(jD), F.E(5))), c0814p, 48, 56);
            }
            c0814p.p(false);
            String strValueOf = String.valueOf(lVar.a);
            L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).l;
            c0814p.X(-2048545977);
            boolean z2 = lVar.c;
            long jV = z2 ? ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).v() : C0861v.g;
            c0814p.p(false);
            mVar.u();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, 1);
            mVar.w();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.f;
            Q4.b(strValueOf, AbstractC0382e.y(qVarW, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), jV, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65528);
            c0814p = c0814p;
            c0814p.X(-2048536336);
            if (lVar.b) {
                com.quizlet.themes.e.a(c0814p).f.getClass();
                androidx.compose.ui.graphics.painter.b bVarQ = com.quizlet.ui.resources.icons.d.q(c0814p);
                if (z2) {
                    c0814p.X(920110907);
                    jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).v();
                    c0814p.p(false);
                } else {
                    c0814p.X(920200311);
                    jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
                    c0814p.p(false);
                }
                C0853m c0853m = new C0853m(jE, 9, Build.VERSION.SDK_INT >= 29 ? c0854n.a(jE, 9) : new PorterDuffColorFilter(F.A(jE), F.E(9)));
                mVar.w();
                androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f2, 7);
                mVar.w();
                AbstractC0460p.c(bVarQ, null, K0.k(qVarY, f2), null, null, DefinitionKt.NO_Float_VALUE, c0853m, c0814p, 48, 56);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(lVar, i, 5);
        }
    }

    public static final void n(View view, Function1 onAttached) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(onAttached, "onAttached");
        if (!view.isAttachedToWindow()) {
            view.addOnAttachStateChangeListener(new V0(view, onAttached, 2));
            return;
        }
        J jF = p0.f(view);
        if (jF != null) {
            onAttached.invoke(jF);
        }
    }

    public static io.reactivex.rxjava3.internal.operators.observable.J o(View clicks) {
        Intrinsics.checkNotNullParameter(clicks, "<this>");
        Intrinsics.f(clicks, "$this$clicks");
        com.jakewharton.rxbinding4.a aVar = new com.jakewharton.rxbinding4.a(clicks);
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        io.reactivex.rxjava3.core.o oVar = io.reactivex.rxjava3.schedulers.e.b;
        Objects.requireNonNull(timeUnit, "unit is null");
        Objects.requireNonNull(oVar, "scheduler is null");
        io.reactivex.rxjava3.internal.operators.observable.J jQ = new m0(aVar, oVar).q(new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(clicks, 7));
        Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
        return jQ;
    }
}
