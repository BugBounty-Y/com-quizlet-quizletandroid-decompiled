package com.google.android.gms.internal.mlkit_vision_common;

import android.util.Base64;
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
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;

/* loaded from: classes2.dex */
public abstract class H2 {
    public static final void a(String str, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        String str2;
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2129305503);
        int i2 = (c0814p.f(str) ? 4 : 2) | i | (c0814p.h(function0) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            str2 = str;
            function02 = function0;
        } else {
            str2 = str;
            function02 = function0;
            K2.a(AbstractC3106b5.d(c0814p, R.string.email_title), null, str2, com.quizlet.features.settings.composables.e.b, function02, c0814p, ((i2 << 6) & 896) | 3072 | ((i2 << 9) & 57344), 2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.l(str2, function02, i, 0);
        }
    }

    public static final void b(com.quizlet.features.settings.data.states.y yVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-512938227);
        int i2 = (c0814p.f(yVar) ? 4 : 2) | i | (c0814p.h(function0) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            function02 = function0;
            K2.a(AbstractC3106b5.d(c0814p, yVar.n), null, null, com.quizlet.features.settings.composables.e.a, function02, c0814p, ((i2 << 9) & 57344) | 3072, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(yVar, function02, i, 6);
        }
    }

    public static final void c(com.quizlet.features.settings.data.states.y settingsUiState, androidx.compose.ui.q qVar, C1608n c1608n, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.q qVar2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(settingsUiState, "settingsUiState");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(201515131);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(settingsUiState) : c0814p2.h(settingsUiState) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            qVar2 = qVar;
            i2 |= c0814p2.f(qVar2) ? 32 : 16;
        } else {
            qVar2 = qVar;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(c1608n) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) != 0 && !c0814p2.w()) {
                c0814p2.Q();
            }
            c0814p2.q();
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(qVar2, null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(314347573, new com.quizlet.features.practicetest.results.i(10, settingsUiState, c1608n), c0814p2), c0814p, (i2 >> 3) & 14, 1022);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 5, settingsUiState, qVar, c1608n);
        }
    }

    public static final void d(com.quizlet.features.settings.data.states.y settingsUiState, androidx.compose.ui.q qVar, C1608n c1608n, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(settingsUiState, "settingsUiState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-521996290);
        int i2 = (c0814p.f(settingsUiState) ? 4 : 2) | i | 48 | (c0814p.f(c1608n) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            int i3 = i & 1;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (i3 == 0 || c0814p.w()) {
                qVar = nVar;
            } else {
                c0814p.Q();
            }
            c0814p.q();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
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
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            M2.c(AbstractC3106b5.d(c0814p, R.string.personal_info_title), null, c0814p, 0);
            com.quizlet.themes.m.g.u();
            c(settingsUiState, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c1608n, c0814p, i2 & 910);
            c0814p.p(true);
        }
        androidx.compose.ui.q qVar2 = qVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 13, qVar2, (Object) settingsUiState, (Object) c1608n);
        }
    }

    public static final void e(String str, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        String str2;
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-922101705);
        int i2 = (c0814p.f(str) ? 4 : 2) | i | (c0814p.h(function0) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            str2 = str;
            function02 = function0;
        } else {
            str2 = str;
            function02 = function0;
            K2.a(AbstractC3106b5.d(c0814p, R.string.username_title), null, str2, com.quizlet.features.settings.composables.e.c, function02, c0814p, ((i2 << 6) & 896) | 3072 | ((i2 << 9) & 57344), 2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.l(str2, function02, i, 1);
        }
    }

    public static final PublicKey f(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        byte[] bArrDecode = Base64.decode(kotlin.text.D.o(kotlin.text.D.o(kotlin.text.D.o(key, "\n", "", false), "-----BEGIN PUBLIC KEY-----", "", false), "-----END PUBLIC KEY-----", "", false), 0);
        Intrinsics.checkNotNullExpressionValue(bArrDecode, "decode(pubKeyString, Base64.DEFAULT)");
        PublicKey publicKeyGeneratePublic = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bArrDecode));
        Intrinsics.checkNotNullExpressionValue(publicKeyGeneratePublic, "kf.generatePublic(x509publicKey)");
        return publicKeyGeneratePublic;
    }

    public static final String g(String kid) {
        Intrinsics.checkNotNullParameter(kid, "kid");
        URL url = new URL("https", "www." + com.facebook.o.q, "/.well-known/oauth/openid/keys/");
        ReentrantLock reentrantLock = new ReentrantLock();
        Condition conditionNewCondition = reentrantLock.newCondition();
        kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
        com.facebook.o.c().execute(new androidx.work.I((Object) url, (Object) j, kid, (Object) reentrantLock, (Object) conditionNewCondition, 2));
        reentrantLock.lock();
        try {
            conditionNewCondition.await(5000L, TimeUnit.MILLISECONDS);
            reentrantLock.unlock();
            return (String) j.a;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public static final boolean h(PublicKey publicKey, String data, String signature) {
        Intrinsics.checkNotNullParameter(publicKey, "publicKey");
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(signature, "signature");
        try {
            Signature signature2 = Signature.getInstance("SHA256withRSA");
            signature2.initVerify(publicKey);
            byte[] bytes = data.getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            signature2.update(bytes);
            byte[] bArrDecode = Base64.decode(signature, 8);
            Intrinsics.checkNotNullExpressionValue(bArrDecode, "decode(signature, Base64.URL_SAFE)");
            return signature2.verify(bArrDecode);
        } catch (Exception unused) {
            return false;
        }
    }
}
