package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class F {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 onTermsOfServiceButtonClicked, Function0 onPrivacyPolicyButtonClicked) {
        int i2;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(onTermsOfServiceButtonClicked, "onTermsOfServiceButtonClicked");
        Intrinsics.checkNotNullParameter(onPrivacyPolicyButtonClicked, "onPrivacyPolicyButtonClicked");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1241210434);
        int i3 = 2;
        if ((i & 6) == 0) {
            i2 = (c0814p.h(onTermsOfServiceButtonClicked) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(onPrivacyPolicyButtonClicked) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            qVar2 = qVar;
            i2 |= c0814p.f(qVar2) ? 256 : 128;
        } else {
            qVar2 = qVar;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            String strD = AbstractC3106b5.d(c0814p, R.string.login_legal_text);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.login_legal_privacy_policy_highlighted);
            String strD3 = AbstractC3106b5.d(c0814p, R.string.login_legal_terms_of_service_highlighted);
            AbstractC0809m0 abstractC0809m0 = com.quizlet.themes.g.a;
            androidx.compose.ui.text.D d = new androidx.compose.ui.text.D(((com.quizlet.themes.b) c0814p.j(abstractC0809m0)).b.f(), com.google.android.gms.internal.mlkit_vision_barcode.S5.g(12), (androidx.compose.ui.text.font.u) null, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, com.quizlet.ui.resources.designsystem.generated.a.c, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65500);
            androidx.compose.ui.text.D d2 = new androidx.compose.ui.text.D(((com.quizlet.themes.b) c0814p.j(abstractC0809m0)).b.f(), com.google.android.gms.internal.mlkit_vision_barcode.S5.g(12), (androidx.compose.ui.text.font.u) null, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, com.quizlet.ui.resources.designsystem.generated.a.e, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65500);
            C0984d c0984d = new C0984d();
            int i4 = c0984d.i(d);
            try {
                c0984d.f(strD);
                Unit unit = Unit.a;
                c0984d.h(i4);
                int iM = StringsKt.M(strD, strD3, 0, true, 2);
                int length = strD3.length() + iM;
                if (iM >= 0 && length > 0) {
                    c0984d.c(d2, StringsKt.M(strD, strD3, 0, false, 6), strD3.length() + StringsKt.M(strD, strD3, 0, false, 6));
                    c0984d.b("termsOfService", StringsKt.M(strD, strD3, 0, false, 6), "termsOfService", strD3.length() + StringsKt.M(strD, strD3, 0, false, 6));
                    i3 = 2;
                }
                int iM2 = StringsKt.M(strD, strD2, 0, true, i3);
                int length2 = strD2.length() + iM2;
                if (iM2 >= 0 && length2 > 0) {
                    c0984d.c(d2, StringsKt.M(strD, strD2, 0, false, 6), strD2.length() + StringsKt.M(strD, strD2, 0, false, 6));
                    c0984d.b("privacyPolicy", StringsKt.M(strD, strD2, 0, false, 6), "privacyPolicy", strD2.length() + StringsKt.M(strD, strD2, 0, false, 6));
                }
                boolean z = true;
                C0995g c0995gJ = c0984d.j();
                androidx.compose.ui.text.L lB = androidx.compose.ui.text.L.b(androidx.compose.ui.text.L.d, 0L, 0L, null, null, 0L, 3, 0L, null, 16744447);
                c0814p.X(1063014253);
                boolean zF = c0814p.f(c0995gJ) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32);
                if ((i2 & 14) != 4) {
                    z = false;
                }
                boolean z2 = z | zF;
                Object objI = c0814p.I();
                if (z2 || objI == C0804k.a) {
                    objI = new androidx.lifecycle.compose.d(c0995gJ, onPrivacyPolicyButtonClicked, onTermsOfServiceButtonClicked, 20);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                AbstractC0484d0.c(c0995gJ, qVar2, lB, false, 0, 0, null, (Function1) objI, c0814p, (i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND);
            } catch (Throwable th) {
                c0984d.h(i4);
                throw th;
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 15, qVar, (Object) onTermsOfServiceButtonClicked, (Object) onPrivacyPolicyButtonClicked);
        }
    }
}
