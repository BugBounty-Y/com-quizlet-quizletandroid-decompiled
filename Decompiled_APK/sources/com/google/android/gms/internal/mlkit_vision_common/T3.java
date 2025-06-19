package com.google.android.gms.internal.mlkit_vision_common;

import android.os.Bundle;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3169i5;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class T3 {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String text, Function1 onTextChange) {
        int i2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(onTextChange, "onTextChange");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1230031103);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(text) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(onTextChange) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(qVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.X(-606355369);
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                objI = new androidx.compose.ui.focus.p();
                c0814p2.i0(objI);
            }
            androidx.compose.ui.focus.p pVar = (androidx.compose.ui.focus.p) objI;
            c0814p2.p(false);
            androidx.compose.ui.text.L l = AbstractC3169i5.g(c0814p2).o;
            com.quizlet.themes.m.g.c();
            androidx.compose.foundation.shape.d dVarA = androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.h);
            androidx.compose.material3.D4 d4 = androidx.compose.material3.D4.a;
            int i3 = i2;
            androidx.compose.material3.K4.b(text, onTextChange, androidx.compose.ui.platform.N.G(androidx.compose.ui.focus.a.k(qVar.g(androidx.compose.foundation.layout.K0.c), pVar), "PasteNoteText"), false, false, l, null, com.quizlet.features.universaluploadflow.composables.b.a, null, null, null, false, null, null, null, false, 0, 0, null, dVarA, androidx.compose.material3.D4.c(AbstractC3169i5.f(c0814p2).b.e(), AbstractC3169i5.f(c0814p2).b.e(), AbstractC3169i5.f(c0814p2).b.e(), 0L, AbstractC3169i5.f(c0814p2).A(), AbstractC3169i5.f(c0814p2).A(), AbstractC3169i5.f(c0814p2).A(), AbstractC3169i5.f(c0814p2).A(), 0L, 0L, null, AbstractC3169i5.f(c0814p2).A(), AbstractC3169i5.f(c0814p2).A(), 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, c0814p2, 2147477256), c0814p2, (i3 & 14) | 12582912 | (i3 & ContentType.LONG_FORM_ON_DEMAND), 0, 0, 2096984);
            c0814p = c0814p2;
            Unit unit = Unit.a;
            c0814p.X(-606311385);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new com.quizlet.features.universaluploadflow.composables.c(pVar, null);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.basestudy.ui.d(i, 1, qVar, text, onTextChange);
        }
    }

    public static final Bundle b(String serverClientId, boolean z) {
        Intrinsics.checkNotNullParameter(serverClientId, "serverClientId");
        Bundle bundle = new Bundle();
        bundle.putString("com.google.android.libraries.identity.googleid.BUNDLE_KEY_SERVER_CLIENT_ID", serverClientId);
        bundle.putString("com.google.android.libraries.identity.googleid.BUNDLE_KEY_NONCE", null);
        bundle.putBoolean("com.google.android.libraries.identity.googleid.BUNDLE_KEY_FILTER_BY_AUTHORIZED_ACCOUNTS", true);
        bundle.putString("com.google.android.libraries.identity.googleid.BUNDLE_KEY_LINKED_SERVICE_ID", null);
        bundle.putStringArrayList("com.google.android.libraries.identity.googleid.BUNDLE_KEY_ID_TOKEN_DEPOSITION_SCOPES", null);
        bundle.putBoolean("com.google.android.libraries.identity.googleid.BUNDLE_KEY_REQUEST_VERIFIED_PHONE_NUMBER", false);
        bundle.putBoolean("com.google.android.libraries.identity.googleid.BUNDLE_KEY_AUTO_SELECT_ENABLED", z);
        return bundle;
    }
}
