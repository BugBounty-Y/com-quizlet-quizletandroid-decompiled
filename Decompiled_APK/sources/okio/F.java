package okio;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.logging.Level;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class F extends C5088e {
    public final Socket m;

    public F(Socket socket) {
        Intrinsics.checkNotNullParameter(socket, "socket");
        this.m = socket;
    }

    @Override // okio.C5088e
    public final void j() throws IOException {
        Socket socket = this.m;
        try {
            socket.close();
        } catch (AssertionError e) {
            if (!AbstractC5085b.f(e)) {
                throw e;
            }
            v.a.log(Level.WARNING, "Failed to close timed out socket " + socket, (Throwable) e);
        } catch (Exception e2) {
            v.a.log(Level.WARNING, "Failed to close timed out socket " + socket, (Throwable) e2);
        }
    }

    public final IOException k(IOException iOException) {
        SocketTimeoutException socketTimeoutException = new SocketTimeoutException("timeout");
        if (iOException != null) {
            socketTimeoutException.initCause(iOException);
        }
        return socketTimeoutException;
    }
}
