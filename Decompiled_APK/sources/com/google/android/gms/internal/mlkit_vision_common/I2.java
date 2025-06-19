package com.google.android.gms.internal.mlkit_vision_common;

import android.net.Uri;
import android.os.Bundle;
import android.os.RemoteException;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.navigation.compose.C1278k;
import com.facebook.login.C1566c;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class I2 {
    public static final void a(com.quizlet.features.settings.composables.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1119185546);
        if ((((c0814p.f(nVar) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            K2.a(AbstractC3106b5.d(c0814p, R.string.ads_and_cookies_title), null, null, com.quizlet.features.settings.composables.f.a, nVar.c, c0814p, 3072, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(nVar, i, 29);
        }
    }

    public static final void b(com.quizlet.features.settings.data.states.y settingsUiState, com.quizlet.features.settings.composables.n preferencesActions, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.q qVar2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(settingsUiState, "settingsUiState");
        Intrinsics.checkNotNullParameter(preferencesActions, "preferencesActions");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(958449602);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(settingsUiState) : c0814p2.h(settingsUiState) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(preferencesActions) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            qVar2 = qVar;
            i2 |= c0814p2.f(qVar2) ? 256 : 128;
        } else {
            qVar2 = qVar;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(qVar2, null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(1658995708, new com.quizlet.features.settings.composables.p(settingsUiState, preferencesActions, 0), c0814p2), c0814p, (i2 >> 6) & 14, 1022);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 6, qVar, (Object) settingsUiState, (Object) preferencesActions);
        }
    }

    public static final void c(com.quizlet.features.settings.data.states.y settingsUiState, com.quizlet.features.settings.composables.n preferencesActions, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(settingsUiState, "settingsUiState");
        Intrinsics.checkNotNullParameter(preferencesActions, "preferencesActions");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2071210669);
        int i2 = (c0814p.f(settingsUiState) ? 4 : 2) | i | (c0814p.f(preferencesActions) ? 32 : 16) | 384;
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
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
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            M2.c(AbstractC3106b5.d(c0814p, R.string.preferences_title), null, c0814p, 0);
            com.quizlet.themes.m.g.u();
            b(settingsUiState, preferencesActions, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, i2 & 126);
            c0814p.p(true);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 14, settingsUiState, preferencesActions, qVar2);
        }
    }

    public static final void d(com.quizlet.features.settings.data.states.y yVar, com.quizlet.features.settings.composables.n nVar, androidx.compose.ui.n nVar2, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(152684701);
        if ((((c0814p.f(yVar) ? 4 : 2) | i | (c0814p.f(nVar) ? 32 : 16) | 384) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar2;
        } else {
            androidx.compose.ui.n nVar4 = androidx.compose.ui.n.b;
            K2.a(AbstractC3106b5.d(c0814p, R.string.push_notifications_title), null, null, androidx.compose.runtime.internal.e.e(-238428487, new com.quizlet.features.settings.composables.p(yVar, nVar, 1), c0814p), null, c0814p, 3072, 22);
            nVar3 = nVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.o(yVar, nVar, nVar3, i, 1);
        }
    }

    public static final void e(com.quizlet.features.settings.data.states.y yVar, com.quizlet.features.settings.composables.n nVar, androidx.compose.ui.n nVar2, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1041847012);
        if ((((c0814p.f(yVar) ? 4 : 2) | i | (c0814p.f(nVar) ? 32 : 16) | 384) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar2;
        } else {
            androidx.compose.ui.n nVar4 = androidx.compose.ui.n.b;
            K2.a(AbstractC3106b5.d(c0814p, R.string.sound_effects_title), null, null, androidx.compose.runtime.internal.e.e(1485845888, new com.quizlet.features.settings.composables.p(yVar, nVar, 2), c0814p), null, c0814p, 3072, 22);
            nVar3 = nVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.o(yVar, nVar, nVar3, i, 0);
        }
    }

    public static void f(Uri url) {
        androidx.browser.customtabs.l lVar;
        Intrinsics.checkNotNullParameter(url, "url");
        ReentrantLock reentrantLock = C1566c.d;
        reentrantLock.lock();
        if (C1566c.c == null && (lVar = C1566c.b) != null) {
            C1566c.c = lVar.c(null);
        }
        reentrantLock.unlock();
        reentrantLock.lock();
        androidx.work.impl.model.n nVar = C1566c.c;
        if (nVar != null) {
            try {
                ((android.support.customtabs.b) ((android.support.customtabs.d) nVar.b)).V((androidx.browser.customtabs.g) nVar.c, url, new Bundle());
            } catch (RemoteException unused) {
            }
        }
        C1566c.d.unlock();
    }
}
