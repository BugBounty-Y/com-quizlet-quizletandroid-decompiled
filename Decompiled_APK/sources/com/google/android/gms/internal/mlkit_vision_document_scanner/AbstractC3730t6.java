package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3097a5;
import com.quizlet.quizletandroid.R;
import java.util.NoSuchElementException;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.t6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3730t6 {
    public static final void a(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.m uiState, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1599949385);
        if (((i | (c0814p.h(uiState) ? 4 : 2) | 48 | (c0814p.h(function1) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            Object[] stringArray = AbstractC3097a5.a(c0814p).getStringArray(R.array.learn_round_summary_motivational_headers);
            c0814p.X(-233441816);
            Object objI = c0814p.I();
            if (objI == v) {
                kotlin.random.d random = kotlin.random.e.a;
                Intrinsics.checkNotNullParameter(stringArray, "<this>");
                Intrinsics.checkNotNullParameter(random, "random");
                if (stringArray.length == 0) {
                    throw new NoSuchElementException("Array is empty.");
                }
                int length = stringArray.length;
                random.getClass();
                objI = stringArray[kotlin.random.e.b.d(length)];
                c0814p.i0(objI);
            }
            String str = (String) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-233439138, c0814p, false);
            Object obj = objG;
            if (objG == v) {
                androidx.compose.animation.core.T t = new androidx.compose.animation.core.T(Boolean.FALSE);
                ((androidx.compose.runtime.L0) t.d).setValue(Boolean.TRUE);
                c0814p.i0(t);
                obj = t;
            }
            c0814p.p(false);
            AbstractC0725t3.a(androidx.compose.ui.platform.N.G(nVar, "learn_round_summary_detailed"), null, null, null, null, 0, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), 0L, null, androidx.compose.runtime.internal.e.e(156459418, new com.quizlet.assembly.compose.menu.g(uiState, function1, (androidx.compose.animation.core.T) obj, str, 15), c0814p), c0814p, 805306368, 446);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(i, 2, uiState, qVar2, function1);
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:11:0x0020, code lost:
    
        return com.quizlet.billing.subscriptions.j.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0027, code lost:
    
        if (r2.equals("com.quizlet.quizletandroid.go.autorenewing.1year.trial7day.international.prices.2021") != false) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0030, code lost:
    
        if (r2.equals("com.quizlet.quizletandroid.go.autorenewing.1year.international.prices.2021") != false) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0034, code lost:
    
        return com.quizlet.billing.subscriptions.j.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x003b, code lost:
    
        if (r2.equals("com.quizlet.quizletandroid.teacher.autorenewing.1year.trial30day.bts2021") != false) goto L28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x004f, code lost:
    
        if (r2.equals("com.quizlet.quizletandroid.teacher.autorenewing.1year.bts2021") != false) goto L28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x0053, code lost:
    
        return com.quizlet.billing.subscriptions.j.c;
     */
    /* JADX WARN: Code restructure failed: missing block: B:6:0x0013, code lost:
    
        if (r2.equals("com.quizlet.quizletandroid.plus.autorenewing.1year.international.prices.2021") != false) goto L10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:9:0x001c, code lost:
    
        if (r2.equals("com.quizlet.quizletandroid.plus.autorenewing.1year.trial7day.international.prices.2021") != false) goto L10;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final com.quizlet.billing.subscriptions.j b(java.lang.String r2) {
        /*
            java.lang.String r0 = "sku"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r0)
            int r0 = r2.hashCode()
            switch(r0) {
                case -1195261840: goto L49;
                case -1176876939: goto L3e;
                case -903327769: goto L35;
                case -86215315: goto L2a;
                case -56534438: goto L21;
                case 661986664: goto L16;
                case 1940394491: goto Ld;
                default: goto Lc;
            }
        Lc:
            goto L54
        Ld:
            java.lang.String r0 = "com.quizlet.quizletandroid.plus.autorenewing.1year.international.prices.2021"
            boolean r0 = r2.equals(r0)
            if (r0 == 0) goto L54
            goto L1e
        L16:
            java.lang.String r0 = "com.quizlet.quizletandroid.plus.autorenewing.1year.trial7day.international.prices.2021"
            boolean r0 = r2.equals(r0)
            if (r0 == 0) goto L54
        L1e:
            com.quizlet.billing.subscriptions.j r2 = com.quizlet.billing.subscriptions.j.b
            return r2
        L21:
            java.lang.String r0 = "com.quizlet.quizletandroid.go.autorenewing.1year.trial7day.international.prices.2021"
            boolean r0 = r2.equals(r0)
            if (r0 == 0) goto L54
            goto L32
        L2a:
            java.lang.String r0 = "com.quizlet.quizletandroid.go.autorenewing.1year.international.prices.2021"
            boolean r0 = r2.equals(r0)
            if (r0 == 0) goto L54
        L32:
            com.quizlet.billing.subscriptions.j r2 = com.quizlet.billing.subscriptions.j.a
            return r2
        L35:
            java.lang.String r0 = "com.quizlet.quizletandroid.teacher.autorenewing.1year.trial30day.bts2021"
            boolean r0 = r2.equals(r0)
            if (r0 == 0) goto L54
            goto L51
        L3e:
            java.lang.String r0 = "com.quizlet.quizletandroid.plus.autorenewing.1month"
            boolean r0 = r2.equals(r0)
            if (r0 == 0) goto L54
            com.quizlet.billing.subscriptions.j r2 = com.quizlet.billing.subscriptions.j.d
            return r2
        L49:
            java.lang.String r0 = "com.quizlet.quizletandroid.teacher.autorenewing.1year.bts2021"
            boolean r0 = r2.equals(r0)
            if (r0 == 0) goto L54
        L51:
            com.quizlet.billing.subscriptions.j r2 = com.quizlet.billing.subscriptions.j.c
            return r2
        L54:
            java.lang.IllegalArgumentException r0 = new java.lang.IllegalArgumentException
            java.lang.String r1 = "Unexpected SubscriptionSku: "
            java.lang.String r2 = r1.concat(r2)
            r0.<init>(r2)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3730t6.b(java.lang.String):com.quizlet.billing.subscriptions.j");
    }

    public static final String c(com.quizlet.billing.subscriptions.j jVar) {
        Intrinsics.checkNotNullParameter(jVar, "<this>");
        int iOrdinal = jVar.ordinal();
        if (iOrdinal == 0) {
            return "Free";
        }
        if (iOrdinal == 1) {
            return "Quizlet Go";
        }
        if (iOrdinal == 2) {
            return "Quizlet Plus";
        }
        if (iOrdinal == 3) {
            return "Quizlet Teacher";
        }
        if (iOrdinal == 4) {
            return "Quizlet Plus (monthly)";
        }
        throw new NoWhenBranchMatchedException();
    }
}
