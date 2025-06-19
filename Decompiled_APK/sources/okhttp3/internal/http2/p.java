package okhttp3.internal.http2;

import androidx.compose.animation.d0;
import java.io.IOException;

/* loaded from: classes3.dex */
public abstract class p {
    public static int a(int i, int i2, int i3) throws IOException {
        if ((i2 & 8) != 0) {
            i--;
        }
        if (i3 <= i) {
            return i - i3;
        }
        throw new IOException(d0.p("PROTOCOL_ERROR padding ", i3, " > remaining length ", i));
    }
}
