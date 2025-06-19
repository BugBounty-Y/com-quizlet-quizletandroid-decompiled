package com.google.android.gms.internal.mlkit_vision_common;

import android.os.Bundle;
import android.util.Pair;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.ads.internal.client.zzc;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2023eq;
import com.google.android.gms.internal.ads.Kk;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3579a6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U5;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.b3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3429b3 {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.n nVar, Function0 function0) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1207472957);
        if (((i | 6 | (c0814p.h(function0) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            AbstractC3579a6.e(AbstractC3106b5.d(c0814p, R.string.change_username_confirmation_message), nVar2, AbstractC3106b5.d(c0814p, R.string.change_username_title), androidx.compose.runtime.internal.e.e(348252292, new com.quizlet.features.infra.folder.create.coursefolder.composable.k(10, function0), c0814p), null, 0, c0814p, 3120, 48);
            nVar = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.A(nVar, function0, i, 3);
        }
    }

    public static final void b(com.quizlet.assembly.compose.modals.x xVar, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.assembly.compose.modals.x xVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1924200242);
        int i2 = (c0814p.h(xVar) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            xVar2 = xVar;
        } else {
            c0814p.S();
            if ((i & 1) != 0 && !c0814p.w()) {
                c0814p.Q();
            }
            c0814p.q();
            xVar2 = xVar;
            U5.b(xVar2, null, false, null, null, null, androidx.compose.runtime.internal.e.e(693000087, new com.quizlet.features.questiontypes.fitb.ui.f(xVar, 1), c0814p), c0814p, 1572872 | (i2 & 14), 62);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(xVar2, i, 0);
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0083  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int c(android.os.Bundle r9) {
        /*
            java.lang.String r0 = "com.google.ads.mediation.admob.AdMobAdapter"
            android.os.Bundle r0 = r9.getBundle(r0)
            if (r0 == 0) goto L9
            r9 = r0
        L9:
            java.lang.String r0 = "query_info_type"
            java.lang.String r9 = r9.getString(r0)
            boolean r0 = android.text.TextUtils.isEmpty(r9)
            r1 = 2
            if (r0 == 0) goto L18
            goto L87
        L18:
            int r0 = r9.hashCode()
            r2 = 1
            r3 = 3
            r4 = 4
            r5 = 5
            r6 = 6
            r7 = 7
            r8 = 8
            switch(r0) {
                case 1743582862: goto L79;
                case 1743582863: goto L6f;
                case 1743582864: goto L65;
                case 1743582865: goto L5b;
                case 1743582866: goto L51;
                case 1743582867: goto L47;
                case 1743582868: goto L3d;
                case 1743582869: goto L33;
                case 1743582870: goto L29;
                default: goto L27;
            }
        L27:
            goto L83
        L29:
            java.lang.String r0 = "requester_type_8"
            boolean r9 = r9.equals(r0)
            if (r9 == 0) goto L83
            r9 = r8
            goto L84
        L33:
            java.lang.String r0 = "requester_type_7"
            boolean r9 = r9.equals(r0)
            if (r9 == 0) goto L83
            r9 = r7
            goto L84
        L3d:
            java.lang.String r0 = "requester_type_6"
            boolean r9 = r9.equals(r0)
            if (r9 == 0) goto L83
            r9 = r6
            goto L84
        L47:
            java.lang.String r0 = "requester_type_5"
            boolean r9 = r9.equals(r0)
            if (r9 == 0) goto L83
            r9 = r5
            goto L84
        L51:
            java.lang.String r0 = "requester_type_4"
            boolean r9 = r9.equals(r0)
            if (r9 == 0) goto L83
            r9 = r4
            goto L84
        L5b:
            java.lang.String r0 = "requester_type_3"
            boolean r9 = r9.equals(r0)
            if (r9 == 0) goto L83
            r9 = r3
            goto L84
        L65:
            java.lang.String r0 = "requester_type_2"
            boolean r9 = r9.equals(r0)
            if (r9 == 0) goto L83
            r9 = r1
            goto L84
        L6f:
            java.lang.String r0 = "requester_type_1"
            boolean r9 = r9.equals(r0)
            if (r9 == 0) goto L83
            r9 = r2
            goto L84
        L79:
            java.lang.String r0 = "requester_type_0"
            boolean r9 = r9.equals(r0)
            if (r9 == 0) goto L83
            r9 = 0
            goto L84
        L83:
            r9 = -1
        L84:
            switch(r9) {
                case 0: goto L94;
                case 1: goto L93;
                case 2: goto L92;
                case 3: goto L91;
                case 4: goto L90;
                case 5: goto L8f;
                case 6: goto L8e;
                case 7: goto L8b;
                case 8: goto L88;
                default: goto L87;
            }
        L87:
            return r1
        L88:
            r9 = 10
            return r9
        L8b:
            r9 = 9
            return r9
        L8e:
            return r8
        L8f:
            return r7
        L90:
            return r6
        L91:
            return r5
        L92:
            return r4
        L93:
            return r3
        L94:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3.c(android.os.Bundle):int");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:36:0x006c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String d(java.lang.String r1) {
        /*
            boolean r0 = android.text.TextUtils.isEmpty(r1)
            if (r0 == 0) goto L9
            java.lang.String r1 = "unspecified"
            return r1
        L9:
            int r0 = r1.hashCode()
            switch(r0) {
                case 1743582862: goto L62;
                case 1743582863: goto L58;
                case 1743582864: goto L4e;
                case 1743582865: goto L44;
                case 1743582866: goto L3a;
                case 1743582867: goto L30;
                case 1743582868: goto L26;
                case 1743582869: goto L1c;
                case 1743582870: goto L11;
                default: goto L10;
            }
        L10:
            goto L6c
        L11:
            java.lang.String r0 = "requester_type_8"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L6c
            r0 = 8
            goto L6d
        L1c:
            java.lang.String r0 = "requester_type_7"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L6c
            r0 = 7
            goto L6d
        L26:
            java.lang.String r0 = "requester_type_6"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L6c
            r0 = 6
            goto L6d
        L30:
            java.lang.String r0 = "requester_type_5"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L6c
            r0 = 5
            goto L6d
        L3a:
            java.lang.String r0 = "requester_type_4"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L6c
            r0 = 4
            goto L6d
        L44:
            java.lang.String r0 = "requester_type_3"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L6c
            r0 = 3
            goto L6d
        L4e:
            java.lang.String r0 = "requester_type_2"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L6c
            r0 = 2
            goto L6d
        L58:
            java.lang.String r0 = "requester_type_1"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L6c
            r0 = 1
            goto L6d
        L62:
            java.lang.String r0 = "requester_type_0"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L6c
            r0 = 0
            goto L6d
        L6c:
            r0 = -1
        L6d:
            switch(r0) {
                case 0: goto L89;
                case 1: goto L86;
                case 2: goto L83;
                case 3: goto L80;
                case 4: goto L7d;
                case 5: goto L7a;
                case 6: goto L77;
                case 7: goto L74;
                case 8: goto L71;
                default: goto L70;
            }
        L70:
            return r1
        L71:
            java.lang.String r1 = "8"
            return r1
        L74:
            java.lang.String r1 = "7"
            return r1
        L77:
            java.lang.String r1 = "6"
            return r1
        L7a:
            java.lang.String r1 = "5"
            return r1
        L7d:
            java.lang.String r1 = "4"
            return r1
        L80:
            java.lang.String r1 = "3"
            return r1
        L83:
            java.lang.String r1 = "2"
            return r1
        L86:
            java.lang.String r1 = "1"
            return r1
        L89:
            java.lang.String r1 = "0"
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3.d(java.lang.String):java.lang.String");
    }

    public static String e(zzm zzmVar) {
        Bundle bundle;
        return (zzmVar == null || (bundle = zzmVar.c) == null) ? "unspecified" : bundle.getString("query_info_type");
    }

    public static void f(Kk kk, String str, Pair... pairArr) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.R6)).booleanValue()) {
            AbstractC2270kd.a.execute(new androidx.core.provider.k(kk, str, pairArr, 8));
        }
    }

    public static int g(C2023eq c2023eq) {
        if (c2023eq.r) {
            return 2;
        }
        zzm zzmVar = c2023eq.d;
        zzc zzcVar = zzmVar.s;
        String str = zzmVar.x;
        if (zzcVar == null && str == null) {
            return 1;
        }
        if (zzcVar == null || str == null) {
            return zzcVar != null ? 3 : 4;
        }
        return 5;
    }
}
