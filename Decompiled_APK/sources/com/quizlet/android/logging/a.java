package com.quizlet.android.logging;

import com.google.firebase.crashlytics.internal.common.i;
import com.google.firebase.crashlytics.internal.common.o;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Map;
import javax.net.ssl.SSLException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import timber.log.b;

/* loaded from: classes2.dex */
public final class a extends b {
    public final q b;
    public final com.quizlet.db.token.a c;

    public a(q mCrashlyticsLogger, com.quizlet.db.token.a mAccessTokenManager) {
        Intrinsics.checkNotNullParameter(mCrashlyticsLogger, "mCrashlyticsLogger");
        Intrinsics.checkNotNullParameter(mAccessTokenManager, "mAccessTokenManager");
        this.b = mCrashlyticsLogger;
        this.c = mAccessTokenManager;
    }

    @Override // timber.log.b
    public final boolean j(int i) {
        return i >= 4;
    }

    @Override // timber.log.b
    public final void k(int i, String message, Throwable th) {
        Intrinsics.checkNotNullParameter(message, "message");
        if ((th instanceof UnknownHostException) || (th instanceof SocketTimeoutException) || (th instanceof SocketException) || (th instanceof SSLException)) {
            return;
        }
        Throwable cause = th != null ? th.getCause() : null;
        if ((cause instanceof UnknownHostException) || (cause instanceof SocketTimeoutException) || (cause instanceof SocketException) || (cause instanceof SSLException)) {
            return;
        }
        q qVar = this.b;
        if (th == null || i < 6) {
            String strA = this.c.a();
            if (strA != null) {
                message = D.o(message, strA, "<redacted>", false);
            }
            com.google.firebase.crashlytics.internal.common.q qVar2 = ((com.google.firebase.crashlytics.b) qVar.b).a;
            qVar2.o.a.a(new o(qVar2, System.currentTimeMillis() - qVar2.d, message, 0));
            return;
        }
        com.google.firebase.crashlytics.b bVar = (com.google.firebase.crashlytics.b) qVar.b;
        bVar.getClass();
        Map map = Collections.EMPTY_MAP;
        com.google.firebase.crashlytics.internal.common.q qVar3 = bVar.a;
        qVar3.o.a.a(new i(qVar3, th));
    }
}
