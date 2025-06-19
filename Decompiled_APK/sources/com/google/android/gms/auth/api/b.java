package com.google.android.gms.auth.api;

import android.content.Context;
import android.os.Bundle;
import android.os.Looper;
import androidx.camera.camera2.internal.c0;
import androidx.compose.animation.d0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.internal.e;
import androidx.compose.ui.n;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.common.api.f;
import com.google.android.gms.common.api.g;
import com.google.android.gms.internal.fido.k0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3579a6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U5;
import com.google.android.gms.internal.p000authapi.i;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.features.infra.folder.create.coursefolder.composable.k;
import com.quizlet.features.settings.composables.dialogs.d;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;

/* loaded from: classes2.dex */
public final class b {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    public static final void a(com.quizlet.features.settings.data.models.b bVar, x xVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1117878074);
        int i2 = i | (c0814p.f(bVar) ? 4 : 2) | (c0814p.h(xVar) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            U5.b(xVar, null, false, null, null, function02, e.e(-747775777, new d(bVar, function0, xVar, function02, 1), c0814p), c0814p, ((i2 >> 3) & 14) | 1769480, 30);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.b(bVar, xVar, function0, function02, i, 1);
        }
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, n nVar, String str, Function0 function0, Function0 function02) {
        n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1084343891);
        int i2 = i | 6 | (c0814p.f(str) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128) | (c0814p.h(function02) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            n nVar3 = n.b;
            AbstractC3579a6.e(AbstractC3106b5.d(c0814p, R.string.settings_reauth_google_message), nVar3, str, e.e(787365300, new k(14, function0), c0814p), e.e(-1796951149, new k(15, function02), c0814p), 0, c0814p, 27696 | ((i2 << 3) & 896), 32);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.c(nVar2, str, function0, function02, i, 1);
        }
    }

    public com.google.android.gms.common.api.c c(Context context, Looper looper, c0 c0Var, Object obj, f fVar, g gVar) {
        com.google.android.gms.common.api.c kVar;
        switch (this.a) {
            case 0:
                return new i(context, looper, c0Var, (c) obj, (com.google.android.gms.common.api.internal.n) fVar, (com.google.android.gms.common.api.internal.n) gVar);
            case 1:
                return new com.google.android.gms.auth.api.signin.internal.d(context, looper, c0Var, (GoogleSignInOptions) obj, (com.google.android.gms.common.api.internal.n) fVar, (com.google.android.gms.common.api.internal.n) gVar);
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            default:
                com.google.android.gms.common.api.internal.n nVar = (com.google.android.gms.common.api.internal.n) fVar;
                com.google.android.gms.common.api.internal.n nVar2 = (com.google.android.gms.common.api.internal.n) gVar;
                switch (this.a) {
                    case 2:
                        return new com.google.android.gms.common.internal.service.c(context, looper, c0Var, (com.google.android.gms.common.internal.k) obj, nVar, nVar2);
                    case 3:
                        return new com.google.android.gms.common.moduleinstall.internal.e(context, looper, 308, c0Var, nVar, nVar2);
                    case 4:
                        return new com.google.android.gms.internal.appset.b(context, looper, 300, c0Var, nVar, nVar2);
                    case 5:
                        kVar = new com.google.android.gms.internal.p000authapi.k(context, looper, c0Var, nVar, nVar2);
                        break;
                    case 6:
                        kVar = new com.google.android.gms.internal.p000authapi.d(context, looper, c0Var, nVar, nVar2);
                        break;
                    case 7:
                    case 8:
                    case 9:
                    case 10:
                    default:
                        throw new UnsupportedOperationException("buildClient must be implemented");
                    case 11:
                        return new com.google.mlkit.vision.documentscanner.internal.e(context, looper, 362, c0Var, nVar, nVar2);
                }
                return kVar;
            case 7:
                return new k0(context, looper, 148, c0Var, fVar, gVar);
            case 8:
                return new com.google.android.gms.oss.licenses.d(context, looper, 185, c0Var, fVar, gVar);
            case 9:
                c0Var.getClass();
                Integer num = (Integer) c0Var.g;
                Bundle bundle = new Bundle();
                bundle.putParcelable("com.google.android.gms.signin.internal.clientRequestedAccount", null);
                if (num != null) {
                    bundle.putInt("com.google.android.gms.common.internal.ClientSettings.sessionId", num.intValue());
                }
                bundle.putBoolean("com.google.android.gms.signin.internal.offlineAccessRequested", false);
                bundle.putBoolean("com.google.android.gms.signin.internal.idTokenRequested", false);
                bundle.putString("com.google.android.gms.signin.internal.serverClientId", null);
                bundle.putBoolean("com.google.android.gms.signin.internal.usePromptModeForAuthCode", true);
                bundle.putBoolean("com.google.android.gms.signin.internal.forceCodeForRefreshToken", false);
                bundle.putString("com.google.android.gms.signin.internal.hostedDomain", null);
                bundle.putString("com.google.android.gms.signin.internal.logSessionId", null);
                bundle.putBoolean("com.google.android.gms.signin.internal.waitForAccessTokenRefresh", false);
                return new com.google.android.gms.signin.internal.a(context, looper, c0Var, bundle, fVar, gVar);
            case 10:
                throw d0.l(obj);
        }
    }
}
