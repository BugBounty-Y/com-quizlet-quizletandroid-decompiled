package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import javax.net.ssl.SSLException;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.v6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3746v6 {
    public static final void a(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(723206166);
        int i2 = i | (c0814p2.f(qVar) ? 4 : 2);
        if ((i2 & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, R.string.learn_round_summary_term_list_header), qVar, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).j, c0814p, (i2 << 3) & ContentType.LONG_FORM_ON_DEMAND, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 19, qVar);
        }
    }

    public static final boolean b(Throwable th) {
        return (th instanceof UnknownHostException) || (th instanceof SocketTimeoutException) || (th instanceof SocketException) || (th instanceof SSLException);
    }
}
