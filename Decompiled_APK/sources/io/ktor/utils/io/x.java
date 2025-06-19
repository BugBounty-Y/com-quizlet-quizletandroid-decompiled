package io.ktor.utils.io;

import java.io.IOException;
import java.util.concurrent.CancellationException;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5037v;

/* loaded from: classes3.dex */
public final class x {
    public final Throwable a;

    /* JADX WARN: Multi-variable type inference failed */
    public x(Throwable th) {
        Throwable iOException;
        if (th == 0) {
            iOException = null;
        } else if (th instanceof CancellationException) {
            if (th instanceof InterfaceC5037v) {
                iOException = ((InterfaceC5037v) th).a();
            } else {
                String message = ((CancellationException) th).getMessage();
                iOException = E.a(message == null ? "Channel was cancelled" : message, th);
            }
        } else if ((th instanceof IOException) && (th instanceof InterfaceC5037v)) {
            iOException = ((InterfaceC5037v) th).a();
        } else {
            String message2 = th.getMessage();
            iOException = new IOException(message2 == null ? "Channel was closed" : message2, th);
        }
        this.a = iOException;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final Throwable a() {
        Throwable thA;
        Throwable th = this.a;
        if (th == 0) {
            return null;
        }
        return th instanceof IOException ? th instanceof InterfaceC5037v ? ((InterfaceC5037v) th).a() : new IOException(((IOException) th).getMessage(), th) : (!(th instanceof InterfaceC5037v) || (thA = ((InterfaceC5037v) th).a()) == null) ? E.a(th.getMessage(), th) : thA;
    }
}
