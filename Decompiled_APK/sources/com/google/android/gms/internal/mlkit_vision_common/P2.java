package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import android.os.Looper;
import android.os.RemoteException;
import android.util.Log;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.ads.conversiontracking.d;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class P2 {
    public static final void a(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-448189598);
        if (((i | 6) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            qVar = androidx.compose.ui.n.b;
            com.quizlet.themes.e.a(c0814p).g.getClass();
            c0814p.X(-841891906);
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.logo_hollow_q_twilight, c0814p, 0);
            c0814p.p(false);
            String strD = AbstractC3106b5.d(c0814p, R.string.app_name);
            long j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).u0;
            AbstractC0460p.c(bVarA, strD, androidx.compose.foundation.layout.K0.k(qVar, com.quizlet.themes.m.O), null, null, DefinitionKt.NO_Float_VALUE, new C0853m(j, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(j, 5) : new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(j), androidx.compose.ui.graphics.F.E(5))), c0814p, 0, 56);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 13, qVar);
        }
    }

    public static final void b(com.quizlet.features.settings.data.states.y settingsUiState, androidx.compose.ui.q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(settingsUiState, "settingsUiState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(787627065);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(settingsUiState) : c0814p.h(settingsUiState) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 48;
        if ((i & 384) == 0) {
            i3 |= c0814p.h(function0) ? 256 : 128;
        }
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar2);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.material3.Q4.b(settingsUiState.k, null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).p, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            c0814p.X(-927263694);
            if (settingsUiState.l) {
                com.quizlet.themes.m.g.u();
                nVar = nVar2;
                AbstractC0460p.c(Z4.a(R.drawable.ic_dev_godmode, c0814p, 0), null, androidx.compose.ui.platform.N.G(AbstractC0460p.l(AbstractC0382e.y(nVar2, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), false, null, function0, 7), "versionSectionDevTools"), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 120);
            } else {
                nVar = nVar2;
            }
            c0814p.p(false);
            c0814p.p(true);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 9, settingsUiState, qVar2, function0);
        }
    }

    public static final void c(com.quizlet.features.settings.data.states.y settingsUiState, androidx.compose.ui.n nVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(settingsUiState, "settingsUiState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(402701878);
        int i2 = (c0814p.f(settingsUiState) ? 4 : 2) | i | 48 | (c0814p.h(function0) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            nVar = androidx.compose.ui.n.b;
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.s();
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h);
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0392jG, gVar, c0814p, 48);
            int i3 = c0814p.P;
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
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            a(null, c0814p, 0);
            b(settingsUiState, null, function0, c0814p, i2 & 910);
            c0814p.p(true);
        }
        androidx.compose.ui.n nVar2 = nVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 16, (androidx.compose.ui.q) nVar2, (Object) settingsUiState, (Object) function0);
        }
    }

    public static androidx.room.s d(d.a aVar) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Calling this from your main thread can lead to deadlock");
        }
        try {
            aVar.a.getPackageInfo("com.android.vending", 0);
            try {
                com.google.ads.conversiontracking.s.c(aVar);
                com.google.ads.conversiontracking.t tVar = new com.google.ads.conversiontracking.t();
                Intent intent = new Intent("com.google.android.gms.ads.identifier.service.START");
                intent.setPackage("com.google.android.gms");
                if (!aVar.bindService(intent, tVar, 1)) {
                    throw new IOException("Connection failure");
                }
                try {
                    try {
                        com.google.ads.conversiontracking.v vVar = (com.google.ads.conversiontracking.v) com.google.ads.conversiontracking.w.V(tVar.a());
                        androidx.room.s sVar = new androidx.room.s(vVar.V(), 2, vVar.X());
                        try {
                            return sVar;
                        } catch (IllegalArgumentException e) {
                            return sVar;
                        }
                    } finally {
                        try {
                            aVar.unbindService(tVar);
                        } catch (IllegalArgumentException e2) {
                            Log.i("AdvertisingIdClient", "getAdvertisingIdInfo unbindService failed.", e2);
                        }
                    }
                } catch (RemoteException e3) {
                    Log.i("AdvertisingIdClient", "GMS remote exception ", e3);
                    throw new IOException("Remote exception");
                } catch (InterruptedException unused) {
                    throw new IOException("Interrupted exception");
                }
            } catch (com.google.ads.conversiontracking.j e4) {
                throw new IOException(e4);
            }
        } catch (PackageManager.NameNotFoundException unused2) {
            throw new com.google.ads.conversiontracking.j();
        }
    }
}
