package com.airbnb.lottie;

import android.graphics.Matrix;
import java.io.InterruptedIOException;
import java.net.ProtocolException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.net.UnknownServiceException;
import java.nio.channels.ClosedChannelException;
import javax.net.ssl.SSLException;

/* renamed from: com.airbnb.lottie.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1464d implements x {
    @Override // com.airbnb.lottie.x
    public final void onResult(Object obj) {
        Throwable th = (Throwable) obj;
        C1464d c1464d = LottieAnimationView.q;
        Matrix matrix = com.airbnb.lottie.utils.i.a;
        if (!(th instanceof SocketException) && !(th instanceof ClosedChannelException) && !(th instanceof InterruptedIOException) && !(th instanceof ProtocolException) && !(th instanceof SSLException) && !(th instanceof UnknownHostException) && !(th instanceof UnknownServiceException)) {
            throw new IllegalStateException("Unable to parse composition", th);
        }
        com.airbnb.lottie.utils.c.c("Unable to load composition.", th);
    }
}
