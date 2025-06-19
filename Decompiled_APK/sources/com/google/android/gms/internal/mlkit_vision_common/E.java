package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.view.View;
import androidx.compose.material3.AbstractC0594b4;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.facebook.AuthenticationToken;
import com.facebook.AuthenticationTokenManager$CurrentAuthenticationTokenChangedBroadcastReceiver;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K5;
import com.quizlet.diagrams.ui.DiagramJSBridge;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;

/* loaded from: classes2.dex */
public abstract class E {
    public static final void a(com.quizlet.features.setpage.termlist.data.n nVar, DiagramJSBridge diagramJSBridge, io.ktor.client.plugins.api.d dVar, androidx.compose.ui.n nVar2, Function0 function0, Function1 function1, Function2 function2, kotlin.jvm.functions.d dVar2, kotlin.jvm.functions.c cVar, Function1 function12, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-927266161);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(nVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p2.f(diagramJSBridge) : c0814p2.h(diagramJSBridge) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(dVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.f(nVar2) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.h(function0) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p2.h(function1) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p2.h(function2) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p2.h(dVar2) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i2 |= c0814p2.h(cVar) ? 67108864 : 33554432;
        }
        if ((805306368 & i) == 0) {
            i2 |= c0814p2.h(function12) ? 536870912 : 268435456;
        }
        if ((i2 & 306783379) == 306783378 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            com.quizlet.assembly.compose.menu.s sVarB = K5.b(c0814p2);
            View view = (View) c0814p2.j(AndroidCompositionLocals_androidKt.f);
            boolean zF = c0814p2.f(view);
            Object objI = c0814p2.I();
            if (zF || objI == v) {
                objI = new androidx.compose.ui.platform.B0(view);
                c0814p2.i0(objI);
            }
            c0814p = c0814p2;
            AbstractC0594b4.a(androidx.compose.ui.input.nestedscroll.f.a(nVar2, (androidx.compose.ui.platform.B0) objI, null), null, 0L, 0L, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, androidx.compose.runtime.internal.e.e(692110442, new com.quizlet.features.setpage.termlist.ui.j(dVar, nVar, function12, diagramJSBridge, function0, sVarB, function1, function2, dVar2, cVar), c0814p2), c0814p, 12582912, 126);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.D(nVar, diagramJSBridge, dVar, nVar2, function0, function1, function2, dVar2, cVar, function12, i);
        }
    }

    public static final void b(com.quizlet.features.setpage.termlist.data.p viewState, DiagramJSBridge diagramJSBridge, androidx.compose.ui.n nVar, com.quizlet.features.setpage.termlist.ui.c cVar, Function1 function1, Function0 function0, Function2 function2, kotlin.jvm.functions.d dVar, kotlin.jvm.functions.c cVar2, Function1 function12, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        int i2;
        com.quizlet.features.setpage.termlist.ui.c cVar3;
        com.quizlet.features.setpage.termlist.ui.c cVar4;
        androidx.compose.ui.n nVar3;
        com.quizlet.features.setpage.termlist.ui.c cVar5;
        androidx.compose.ui.n nVar4;
        Intrinsics.checkNotNullParameter(viewState, "viewState");
        Intrinsics.checkNotNullParameter(diagramJSBridge, "diagramJSBridge");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1162761399);
        int i3 = i | (c0814p.f(viewState) ? 4 : 2) | (c0814p.h(diagramJSBridge) ? 32 : 16) | 1408 | (c0814p.h(function1) ? 16384 : 8192) | (c0814p.h(function0) ? 131072 : 65536) | (c0814p.h(function2) ? 1048576 : 524288) | (c0814p.h(dVar) ? 8388608 : 4194304) | (c0814p.h(cVar2) ? 67108864 : 33554432) | (c0814p.h(function12) ? 536870912 : 268435456);
        if ((306783379 & i3) == 306783378 && c0814p.x()) {
            c0814p.Q();
            nVar4 = nVar;
            cVar5 = cVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                nVar2 = androidx.compose.ui.n.b;
                c0814p.X(-1113093233);
                Object objB = K6.b(com.quizlet.features.setpage.termlist.ui.c.class, ((Context) c0814p.j(AndroidCompositionLocals_androidKt.b)).getApplicationContext());
                c0814p.p(false);
                com.quizlet.features.setpage.termlist.ui.c cVar6 = (com.quizlet.features.setpage.termlist.ui.c) objB;
                i2 = i3 & (-7169);
                cVar3 = cVar6;
            } else {
                c0814p.Q();
                nVar2 = nVar;
                i2 = i3 & (-7169);
                cVar3 = cVar;
            }
            c0814p.q();
            if (viewState instanceof com.quizlet.features.setpage.termlist.data.o) {
                cVar4 = cVar3;
                nVar3 = nVar2;
            } else {
                if (!(viewState instanceof com.quizlet.features.setpage.termlist.data.n)) {
                    throw new NoWhenBranchMatchedException();
                }
                com.quizlet.quizletandroid.u uVar = (com.quizlet.quizletandroid.u) cVar3;
                int i4 = i2;
                cVar4 = cVar3;
                nVar3 = nVar2;
                a((com.quizlet.features.setpage.termlist.data.n) viewState, diagramJSBridge, new io.ktor.client.plugins.api.d(new com.quizlet.shared.usecase.studiableMetadata.a(25), uVar.m0(), new androidx.work.impl.model.i(new com.google.mlkit.vision.documentscanner.internal.c(uVar.v0), uVar.o0(), new com.quizlet.ads.helper.b(uVar.q()), com.quizlet.featuregate.injection.a.f())), nVar3, function0, function1, function2, dVar, cVar2, function12, c0814p, (i4 & ContentType.LONG_FORM_ON_DEMAND) | 3136 | (57344 & (i4 >> 3)) | ((i4 << 3) & 458752) | (3670016 & i4) | (29360128 & i4) | (234881024 & i4) | (1879048192 & i4));
            }
            cVar5 = cVar4;
            nVar4 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.detail.c(viewState, diagramJSBridge, nVar4, cVar5, function1, function0, function2, dVar, cVar2, function12, i);
        }
    }

    public static void c(AuthenticationToken authenticationToken) {
        com.quizlet.shared.usecase.studiableMetadata.a aVar = com.facebook.h.d;
        com.facebook.h hVar = com.facebook.h.e;
        if (hVar == null) {
            synchronized (aVar) {
                hVar = com.facebook.h.e;
                if (hVar == null) {
                    androidx.localbroadcastmanager.content.b bVarA = androidx.localbroadcastmanager.content.b.a(com.facebook.o.a());
                    Intrinsics.checkNotNullExpressionValue(bVarA, "getInstance(applicationContext)");
                    com.facebook.h hVar2 = new com.facebook.h(bVarA, new com.airbnb.lottie.network.d(21));
                    com.facebook.h.e = hVar2;
                    hVar = hVar2;
                }
            }
        }
        AuthenticationToken authenticationToken2 = (AuthenticationToken) hVar.c;
        hVar.c = authenticationToken;
        com.airbnb.lottie.network.d dVar = (com.airbnb.lottie.network.d) hVar.b;
        if (authenticationToken != null) {
            Intrinsics.checkNotNullParameter(authenticationToken, "authenticationToken");
            try {
                ((SharedPreferences) dVar.b).edit().putString("com.facebook.AuthenticationManager.CachedAuthenticationToken", authenticationToken.a().toString()).apply();
            } catch (JSONException unused) {
            }
        } else {
            ((SharedPreferences) dVar.b).edit().remove("com.facebook.AuthenticationManager.CachedAuthenticationToken").apply();
            com.facebook.internal.J.c(com.facebook.o.a());
        }
        if (authenticationToken2 == null ? authenticationToken == null : authenticationToken2.equals(authenticationToken)) {
            return;
        }
        Intent intent = new Intent(com.facebook.o.a(), (Class<?>) AuthenticationTokenManager$CurrentAuthenticationTokenChangedBroadcastReceiver.class);
        intent.setAction("com.facebook.sdk.ACTION_CURRENT_AUTHENTICATION_TOKEN_CHANGED");
        intent.putExtra("com.facebook.sdk.EXTRA_OLD_AUTHENTICATION_TOKEN", authenticationToken2);
        intent.putExtra("com.facebook.sdk.EXTRA_NEW_AUTHENTICATION_TOKEN", authenticationToken);
        hVar.a.c(intent);
    }
}
