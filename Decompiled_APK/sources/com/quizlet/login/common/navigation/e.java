package com.quizlet.login.common.navigation;

import android.content.Intent;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.navigation.B;
import androidx.navigation.E;
import androidx.navigation.H;
import androidx.navigation.W;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3180j7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3207m7;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_barcode.M7;
import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.google.android.gms.internal.mlkit_vision_camera.J1;
import com.google.android.gms.internal.mlkit_vision_camera.O1;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.quizlet.data.model.C2;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.widgets.o;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class e {
    public static final /* synthetic */ int a = 0;

    public static final void a(C2 streakData, androidx.appcompat.view.a linkProvider, androidx.glance.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(streakData, "streakData");
        Intrinsics.checkNotNullParameter(linkProvider, "linkProvider");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(397094742);
        if ((((c0814p.h(streakData) ? 4 : 2) | i | (c0814p.f(linkProvider) ? 32 : 16) | 384) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            nVar = androidx.glance.n.a;
            M7.a(AbstractC3207m7.b(AbstractC3180j7.b(AbstractC3332e.d(nVar), new androidx.glance.a(R.drawable.bg_widget)), androidx.glance.appwidget.action.g.a(linkProvider.b())), androidx.glance.layout.c.f, androidx.compose.runtime.internal.e.e(1014880568, new o(okhttp3.internal.platform.d.b(streakData) ? R.drawable.bg_shape_fire_half_vcut_on : R.drawable.bg_shape_fire_half_vcut_off, streakData, 0), c0814p), c0814p, 384, 0);
        }
        androidx.glance.n nVar2 = nVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(i, 11, streakData, linkProvider, nVar2);
        }
    }

    public static final void b(final Intent originIntent, final String startDestination, final boolean z, final boolean z2, final String str, H h, com.quizlet.quizletandroid.ui.navigationmanagers.d dVar, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        final com.quizlet.quizletandroid.ui.navigationmanagers.d dVar2;
        final H h2;
        final com.quizlet.quizletandroid.ui.navigationmanagers.d dVar3;
        final H h3;
        Intrinsics.checkNotNullParameter(originIntent, "originIntent");
        Intrinsics.checkNotNullParameter(startDestination, "startDestination");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1194524894);
        int i3 = i | (c0814p.h(originIntent) ? 4 : 2) | (c0814p.f(startDestination) ? 32 : 16) | (c0814p.g(z) ? 256 : 128) | (c0814p.g(z2) ? 2048 : 1024) | (c0814p.f(str) ? 16384 : 8192) | 589824;
        if ((599187 & i3) == 599186 && c0814p.x()) {
            c0814p.Q();
            h3 = h;
            dVar3 = dVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                H hD = O1.d(new W[0], c0814p);
                c0814p.X(1907377511);
                Object objB = K6.b(com.quizlet.login.di.a.class, c0814p.j(AndroidCompositionLocals_androidKt.b));
                c0814p.p(false);
                i2 = i3 & (-4128769);
                dVar2 = (com.quizlet.quizletandroid.ui.navigationmanagers.d) ((C4622e) ((com.quizlet.login.di.a) objB)).H.get();
                h2 = hD;
            } else {
                c0814p.Q();
                i2 = i3 & (-4128769);
                h2 = h;
                dVar2 = dVar;
            }
            c0814p.q();
            c0814p.X(-1338516303);
            boolean zH = ((i2 & 896) == 256) | ((57344 & i2) == 16384) | c0814p.h(originIntent) | c0814p.h(dVar2) | c0814p.h(h2) | ((i2 & 7168) == 2048);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new Function1() { // from class: com.quizlet.login.common.navigation.a
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        E NavHost = (E) obj;
                        Intrinsics.checkNotNullParameter(NavHost, "$this$NavHost");
                        h hVar = new h(z, str, originIntent);
                        com.quizlet.quizletandroid.ui.navigationmanagers.d dVar4 = dVar2;
                        H h4 = h2;
                        N5.d(NavHost, hVar, new androidx.compose.runtime.internal.d(true, -1045257567, new c(dVar4, h4, 0)));
                        N5.d(NavHost, j.a, new androidx.compose.runtime.internal.d(true, -628727784, new c(h4, dVar4, 1)));
                        N5.d(NavHost, m.a, new androidx.compose.runtime.internal.d(true, 589551833, new com.quizlet.features.notes.detail.navigation.d(h4, 11)));
                        boolean z3 = z2;
                        N5.d(NavHost, new n(z3), new androidx.compose.runtime.internal.d(true, 1807831450, new c(h4, dVar4, 2)));
                        N5.d(NavHost, i.a, new androidx.compose.runtime.internal.d(true, -1268856229, new com.quizlet.features.notes.detail.navigation.d(h4, 12)));
                        N5.d(NavHost, f.a, new androidx.compose.runtime.internal.d(true, -50576612, new com.quizlet.features.notes.detail.navigation.d(h4, 13)));
                        N5.d(NavHost, new l(z3), new androidx.compose.runtime.internal.d(true, 1167703005, new c(dVar4, h4, 3)));
                        N5.e(NavHost, k.a, new androidx.compose.runtime.internal.d(true, 839336604, new com.quizlet.features.notes.detail.navigation.d(h4, 14)));
                        return Unit.a;
                    }
                };
                c0814p.i0(objI);
            }
            c0814p.p(false);
            Q1.d(h2, startDestination, null, (Function1) objI, c0814p, i2 & ContentType.LONG_FORM_ON_DEMAND, 12);
            dVar3 = dVar2;
            h3 = h2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(originIntent, startDestination, z, z2, str, h3, dVar3, i) { // from class: com.quizlet.login.common.navigation.b
                public final /* synthetic */ Intent a;
                public final /* synthetic */ String b;
                public final /* synthetic */ boolean c;
                public final /* synthetic */ boolean d;
                public final /* synthetic */ String e;
                public final /* synthetic */ H f;
                public final /* synthetic */ com.quizlet.quizletandroid.ui.navigationmanagers.d g;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    String str2 = this.b;
                    H h4 = this.f;
                    com.quizlet.quizletandroid.ui.navigationmanagers.d dVar4 = this.g;
                    e.b(this.a, str2, this.c, this.d, this.e, h4, dVar4, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void c(H h, String email) {
        Intrinsics.checkNotNullParameter(h, "<this>");
        Intrinsics.checkNotNullParameter(email, "email");
        B bK = h.b.h().k("email_sent");
        if (bK == null) {
            return;
        }
        h.b(bK.b.c, AbstractC3206m6.a(new Pair("email", email)), J1.c(new com.quizlet.features.notes.detail.navigation.e(h, 1)));
    }

    public static final void d(H h, String email) {
        Intrinsics.checkNotNullParameter(h, "<this>");
        Intrinsics.checkNotNullParameter(email, "email");
        B bK = h.b.h().k("multiple_accounts_found");
        if (bK == null) {
            return;
        }
        h.b(bK.b.c, AbstractC3206m6.a(new Pair("email", email)), null);
    }
}
