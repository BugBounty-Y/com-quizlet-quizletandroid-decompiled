package com.google.android.gms.internal.mlkit_vision_common;

import android.os.Bundle;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3587b6;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class U3 {
    public static final void a(int i, com.quizlet.data.model.m2 source, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i2) {
        Intrinsics.checkNotNullParameter(source, "source");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-119906729);
        if ((((c0814p.d(i) ? 4 : 2) | i2 | (c0814p.f(source) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long j = ((com.quizlet.themes.b) c0814p.j(b)).W0;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.d();
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVar, j, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.g));
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVarF, f);
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            C0380d c0380d = AbstractC0398m.a;
            mVar.s();
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g(f), hVar, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.themes.e.a(c0814p).g.getClass();
            c0814p.X(923439946);
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.logo_hollow_qplus_twilight, c0814p, 0);
            c0814p.p(false);
            AbstractC3587b6.d(bVarA, null, null, ((com.quizlet.themes.b) c0814p.j(b)).u(), ((com.quizlet.themes.b) c0814p.j(b)).G(), c0814p, 0, 6);
            Intrinsics.checkNotNullParameter(source, "<this>");
            c0814p.X(1099193870);
            if (source == com.quizlet.data.model.m2.a) {
                throw new kotlin.n(null, 1, null);
            }
            if (source == com.quizlet.data.model.m2.b) {
                throw new kotlin.n(null, 1, null);
            }
            if (source != com.quizlet.data.model.m2.c) {
                throw new NoWhenBranchMatchedException();
            }
            String strB = AbstractC3106b5.b(R.plurals.uuf_remaining_tests_upload_message, i, new Object[]{Integer.valueOf(i)}, c0814p);
            c0814p.p(false);
            androidx.compose.material3.Q4.b(strB, androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f), ((com.quizlet.themes.b) c0814p.j(b)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).k, c0814p, 48, 0, 65528);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.upload.a(i, source, qVar, i2);
        }
    }

    public static final Bundle b(String serverClientId) {
        Intrinsics.checkNotNullParameter(serverClientId, "serverClientId");
        Bundle bundle = new Bundle();
        bundle.putString("com.google.android.libraries.identity.googleid.siwg.BUNDLE_KEY_SERVER_CLIENT_ID", serverClientId);
        bundle.putString("com.google.android.libraries.identity.googleid.siwg.BUNDLE_KEY_NONCE", null);
        bundle.putString("com.google.android.libraries.identity.googleid.siwg.BUNDLE_KEY_HOSTED_DOMAIN_FILTER", null);
        bundle.putBoolean("com.google.android.libraries.identity.googleid.siwg.BUNDLE_KEY_AUTO_SELECT_ENABLED", true);
        bundle.putString("com.google.android.libraries.identity.googleid.BUNDLE_KEY_GOOGLE_ID_TOKEN_SUBTYPE", "com.google.android.libraries.identity.googleid.TYPE_GOOGLE_ID_TOKEN_SIWG_CREDENTIAL");
        return bundle;
    }
}
