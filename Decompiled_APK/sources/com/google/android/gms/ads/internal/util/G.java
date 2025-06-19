package com.google.android.gms.ads.internal.util;

import android.app.Activity;
import android.content.Context;
import android.media.AudioManager;
import android.os.Process;
import android.telephony.TelephonyManager;
import android.webkit.CookieManager;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class G {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1482365832);
        int i2 = i | (c0814p.f(qVar) ? 4 : 2) | (c0814p.h(function0) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            V v = C0804k.a;
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
            Q4.b(AbstractC3106b5.d(c0814p, R.string.delete_account_confirmation_description), null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).o, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.q();
            androidx.compose.ui.q qVarC2 = K0.c(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 1.0f);
            String strD = AbstractC3106b5.d(c0814p, R.string.delete_account_confirmation_button);
            C4076a c4076a = C4076a.g;
            c0814p.X(-1524335987);
            boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            if (z || objI == v) {
                objI = new com.quizlet.features.setpage.composable.a(14, function0);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            W4.a(strD, qVarC2, (Function0) objI, false, c4076a, null, null, null, null, false, c0814p, 0, 1000);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.b(qVar, function0, i, 4);
        }
    }

    public static CookieManager b() {
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        F f = jVar.c;
        int iMyUid = Process.myUid();
        if (iMyUid == 0 || iMyUid == 1000) {
            return null;
        }
        try {
            return CookieManager.getInstance();
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.i.f("Failed to obtain CookieManager.", th);
            jVar.h.g("ApiLevelUtil.getCookieManager", th);
            return null;
        }
    }

    public int c(AudioManager audioManager) {
        return 0;
    }

    public void d(Activity activity) {
    }

    public int e(Context context) {
        return ((TelephonyManager) context.getSystemService("phone")).getNetworkType();
    }
}
