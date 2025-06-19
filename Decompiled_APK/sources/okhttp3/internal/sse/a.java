package okhttp3.internal.sse;

import com.quizlet.quizletandroid.ui.common.images.capture.b;
import io.reactivex.rxjava3.internal.operators.single.i;
import java.io.EOFException;
import kotlin.jvm.internal.Intrinsics;
import okio.AbstractC5085b;
import okio.C5091h;
import okio.InterfaceC5093j;
import okio.k;
import okio.w;

/* loaded from: classes3.dex */
public final class a {
    public static final w d;
    public static final k e;
    public final InterfaceC5093j a;
    public final i b;
    public String c;

    static {
        int i = w.d;
        k kVar = k.d;
        d = AbstractC5085b.g(b.i("\r\n"), b.i("\r"), b.i("\n"), b.i("data: "), b.i("data:"), b.i("data\r\n"), b.i("data\r"), b.i("data\n"), b.i("id: "), b.i("id:"), b.i("id\r\n"), b.i("id\r"), b.i("id\n"), b.i("event: "), b.i("event:"), b.i("event\r\n"), b.i("event\r"), b.i("event\n"), b.i("retry: "), b.i("retry:"));
        e = b.i("\r\n");
    }

    public a(InterfaceC5093j source, i callback) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(callback, "callback");
        this.a = source;
        this.b = callback;
    }

    public final boolean a() throws NumberFormatException, EOFException {
        long j;
        String strS = this.c;
        C5091h c5091h = new C5091h();
        while (true) {
            String strS2 = null;
            while (true) {
                InterfaceC5093j interfaceC5093j = this.a;
                w wVar = d;
                int iJ0 = interfaceC5093j.j0(wVar);
                i iVar = this.b;
                if (iJ0 >= 0 && iJ0 < 3) {
                    if (c5091h.b == 0) {
                        return true;
                    }
                    this.c = strS;
                    c5091h.skip(1L);
                    String data = c5091h.U();
                    iVar.getClass();
                    Intrinsics.checkNotNullParameter(data, "data");
                    ((okhttp3.sse.b) iVar.a).onEvent(iVar, strS, strS2, data);
                    return true;
                }
                k kVar = e;
                if (3 <= iJ0 && iJ0 < 5) {
                    c5091h.p0(10);
                    interfaceC5093j.w(c5091h, interfaceC5093j.x(kVar));
                    interfaceC5093j.j0(wVar);
                } else if (5 <= iJ0 && iJ0 < 8) {
                    c5091h.p0(10);
                } else if (8 <= iJ0 && iJ0 < 10) {
                    strS = interfaceC5093j.S();
                    if (strS.length() <= 0) {
                        strS = null;
                    }
                } else if (10 <= iJ0 && iJ0 < 13) {
                    strS = null;
                } else if (13 <= iJ0 && iJ0 < 15) {
                    strS2 = interfaceC5093j.S();
                    if (strS2.length() > 0) {
                    }
                } else if (15 > iJ0 || iJ0 >= 18) {
                    if (18 <= iJ0 && iJ0 < 20) {
                        String strS3 = interfaceC5093j.S();
                        byte[] bArr = okhttp3.internal.b.a;
                        Intrinsics.checkNotNullParameter(strS3, "<this>");
                        try {
                            j = Long.parseLong(strS3);
                        } catch (NumberFormatException unused) {
                            j = -1;
                        }
                        if (j != -1) {
                            iVar.getClass();
                        }
                    } else {
                        if (iJ0 != -1) {
                            throw new AssertionError();
                        }
                        long jX = interfaceC5093j.x(kVar);
                        if (jX == -1) {
                            return false;
                        }
                        interfaceC5093j.skip(jX);
                        interfaceC5093j.j0(wVar);
                    }
                }
            }
        }
    }
}
