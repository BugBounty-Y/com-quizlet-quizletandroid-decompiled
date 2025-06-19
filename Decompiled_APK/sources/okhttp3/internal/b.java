package okhttp3.internal;

import androidx.collection.Y;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import java.io.Closeable;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import kotlin.text.Charsets;
import kotlin.text.D;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import okhttp3.A;
import okhttp3.H;
import okhttp3.I;
import okhttp3.r;
import okhttp3.s;
import okio.AbstractC5085b;
import okio.C5091h;
import okio.G;
import okio.InterfaceC5093j;
import okio.k;
import okio.w;

/* loaded from: classes3.dex */
public abstract class b {
    public static final byte[] a;
    public static final r b = AbstractC3343g2.d(new String[0]);
    public static final I c;
    public static final w d;
    public static final TimeZone e;
    public static final Regex f;
    public static final String g;

    static {
        byte[] bArr = new byte[0];
        a = bArr;
        Intrinsics.checkNotNullParameter(bArr, "<this>");
        C5091h c5091h = new C5091h();
        c5091h.n0(bArr);
        long j = 0;
        Intrinsics.checkNotNullParameter(c5091h, "<this>");
        c = new I((okhttp3.w) null, j, c5091h);
        Intrinsics.checkNotNullParameter(bArr, "<this>");
        c(j, j, j);
        int i = w.d;
        k kVar = k.d;
        d = AbstractC5085b.g(com.quizlet.quizletandroid.ui.common.images.capture.b.g("efbbbf"), com.quizlet.quizletandroid.ui.common.images.capture.b.g("feff"), com.quizlet.quizletandroid.ui.common.images.capture.b.g("fffe"), com.quizlet.quizletandroid.ui.common.images.capture.b.g("0000ffff"), com.quizlet.quizletandroid.ui.common.images.capture.b.g("ffff0000"));
        TimeZone timeZone = TimeZone.getTimeZone("GMT");
        Intrinsics.d(timeZone);
        e = timeZone;
        f = new Regex("([0-9a-fA-F]*:[0-9a-fA-F:.]*)|([\\d.]+)");
        String name = A.class.getName();
        Intrinsics.checkNotNullExpressionValue(name, "OkHttpClient::class.java.name");
        g = StringsKt.U(StringsKt.T(name, "okhttp3."), "Client");
    }

    public static final String A(int i, int i2, String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        int iO = o(i, i2, str);
        String strSubstring = str.substring(iO, p(iO, i2, str));
        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
        return strSubstring;
    }

    public static final boolean a(s sVar, s other) {
        Intrinsics.checkNotNullParameter(sVar, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        return Intrinsics.b(sVar.d, other.d) && sVar.e == other.e && Intrinsics.b(sVar.a, other.a);
    }

    public static final int b(String name, long j, TimeUnit timeUnit) {
        Intrinsics.checkNotNullParameter(name, "name");
        if (j < 0) {
            throw new IllegalStateException(name.concat(" < 0").toString());
        }
        if (timeUnit == null) {
            throw new IllegalStateException("unit == null");
        }
        long millis = timeUnit.toMillis(j);
        if (millis > 2147483647L) {
            throw new IllegalArgumentException(name.concat(" too large.").toString());
        }
        if (millis != 0 || j <= 0) {
            return (int) millis;
        }
        throw new IllegalArgumentException(name.concat(" too small.").toString());
    }

    public static final void c(long j, long j2, long j3) {
        if ((j2 | j3) < 0 || j2 > j || j - j2 < j3) {
            throw new ArrayIndexOutOfBoundsException();
        }
    }

    public static final void d(Closeable closeable) throws IOException {
        Intrinsics.checkNotNullParameter(closeable, "<this>");
        try {
            closeable.close();
        } catch (RuntimeException e2) {
            throw e2;
        } catch (Exception unused) {
        }
    }

    public static final void e(Socket socket) {
        Intrinsics.checkNotNullParameter(socket, "<this>");
        try {
            socket.close();
        } catch (AssertionError e2) {
            throw e2;
        } catch (RuntimeException e3) {
            if (!Intrinsics.b(e3.getMessage(), "bio == null")) {
                throw e3;
            }
        } catch (Exception unused) {
        }
    }

    public static final int f(String str, char c2, int i, int i2) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        while (i < i2) {
            if (str.charAt(i) == c2) {
                return i;
            }
            i++;
        }
        return i2;
    }

    public static final int g(String str, int i, String delimiters, int i2) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(delimiters, "delimiters");
        while (i < i2) {
            if (StringsKt.F(delimiters, str.charAt(i), false)) {
                return i;
            }
            i++;
        }
        return i2;
    }

    public static /* synthetic */ int h(String str, char c2, int i, int i2, int i3) {
        if ((i3 & 2) != 0) {
            i = 0;
        }
        if ((i3 & 4) != 0) {
            i2 = str.length();
        }
        return f(str, c2, i, i2);
    }

    public static final boolean i(G g2) {
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        Intrinsics.checkNotNullParameter(g2, "<this>");
        Intrinsics.checkNotNullParameter(timeUnit, "timeUnit");
        try {
            return v(g2, 100);
        } catch (IOException unused) {
            return false;
        }
    }

    public static final String j(String format, Object... args) {
        Intrinsics.checkNotNullParameter(format, "format");
        Intrinsics.checkNotNullParameter(args, "args");
        Locale locale = Locale.US;
        Object[] objArrCopyOf = Arrays.copyOf(args, args.length);
        String str = String.format(locale, format, Arrays.copyOf(objArrCopyOf, objArrCopyOf.length));
        Intrinsics.checkNotNullExpressionValue(str, "format(locale, format, *args)");
        return str;
    }

    public static final boolean k(String[] strArr, String[] strArr2, Comparator comparator) {
        Intrinsics.checkNotNullParameter(strArr, "<this>");
        Intrinsics.checkNotNullParameter(comparator, "comparator");
        if (strArr.length != 0 && strArr2 != null && strArr2.length != 0) {
            for (String str : strArr) {
                Y yF = O.f(strArr2);
                while (yF.hasNext()) {
                    if (comparator.compare(str, (String) yF.next()) == 0) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public static final long l(H h) {
        Intrinsics.checkNotNullParameter(h, "<this>");
        String strA = h.f.a("Content-Length");
        if (strA != null) {
            Intrinsics.checkNotNullParameter(strA, "<this>");
            try {
                return Long.parseLong(strA);
            } catch (NumberFormatException unused) {
            }
        }
        return -1L;
    }

    public static final List m(Object... elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        Object[] objArr = (Object[]) elements.clone();
        List listUnmodifiableList = Collections.unmodifiableList(B.j(Arrays.copyOf(objArr, objArr.length)));
        Intrinsics.checkNotNullExpressionValue(listUnmodifiableList, "unmodifiableList(listOf(*elements.clone()))");
        return listUnmodifiableList;
    }

    public static final int n(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        int length = str.length();
        for (int i = 0; i < length; i++) {
            char cCharAt = str.charAt(i);
            if (Intrinsics.g(cCharAt, 31) <= 0 || Intrinsics.g(cCharAt, 127) >= 0) {
                return i;
            }
        }
        return -1;
    }

    public static final int o(int i, int i2, String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        while (i < i2) {
            char cCharAt = str.charAt(i);
            if (cCharAt != '\t' && cCharAt != '\n' && cCharAt != '\f' && cCharAt != '\r' && cCharAt != ' ') {
                return i;
            }
            i++;
        }
        return i2;
    }

    public static final int p(int i, int i2, String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        int i3 = i2 - 1;
        if (i <= i3) {
            while (true) {
                char cCharAt = str.charAt(i3);
                if (cCharAt != '\t' && cCharAt != '\n' && cCharAt != '\f' && cCharAt != '\r' && cCharAt != ' ') {
                    return i3 + 1;
                }
                if (i3 == i) {
                    break;
                }
                i3--;
            }
        }
        return i;
    }

    public static final String[] q(String[] strArr, String[] other, Comparator comparator) {
        Intrinsics.checkNotNullParameter(strArr, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        Intrinsics.checkNotNullParameter(comparator, "comparator");
        ArrayList arrayList = new ArrayList();
        for (String str : strArr) {
            int length = other.length;
            int i = 0;
            while (true) {
                if (i >= length) {
                    break;
                }
                if (comparator.compare(str, other[i]) == 0) {
                    arrayList.add(str);
                    break;
                }
                i++;
            }
        }
        return (String[]) arrayList.toArray(new String[0]);
    }

    public static final boolean r(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        return D.l(name, "Authorization", true) || D.l(name, "Cookie", true) || D.l(name, "Proxy-Authorization", true) || D.l(name, "Set-Cookie", true);
    }

    public static final int s(char c2) {
        if ('0' <= c2 && c2 < ':') {
            return c2 - '0';
        }
        if ('a' <= c2 && c2 < 'g') {
            return c2 - 'W';
        }
        if ('A' > c2 || c2 >= 'G') {
            return -1;
        }
        return c2 - '7';
    }

    public static final Charset t(InterfaceC5093j interfaceC5093j, Charset charset) {
        Intrinsics.checkNotNullParameter(interfaceC5093j, "<this>");
        Intrinsics.checkNotNullParameter(charset, "default");
        int iJ0 = interfaceC5093j.j0(d);
        if (iJ0 == -1) {
            return charset;
        }
        if (iJ0 == 0) {
            Charset UTF_8 = StandardCharsets.UTF_8;
            Intrinsics.checkNotNullExpressionValue(UTF_8, "UTF_8");
            return UTF_8;
        }
        if (iJ0 == 1) {
            Charset UTF_16BE = StandardCharsets.UTF_16BE;
            Intrinsics.checkNotNullExpressionValue(UTF_16BE, "UTF_16BE");
            return UTF_16BE;
        }
        if (iJ0 == 2) {
            Charset UTF_16LE = StandardCharsets.UTF_16LE;
            Intrinsics.checkNotNullExpressionValue(UTF_16LE, "UTF_16LE");
            return UTF_16LE;
        }
        if (iJ0 == 3) {
            Charsets.a.getClass();
            Charset charset2 = Charsets.e;
            if (charset2 != null) {
                return charset2;
            }
            Charset charsetForName = Charset.forName("UTF-32BE");
            Intrinsics.checkNotNullExpressionValue(charsetForName, "forName(...)");
            Charsets.e = charsetForName;
            return charsetForName;
        }
        if (iJ0 != 4) {
            throw new AssertionError();
        }
        Charsets.a.getClass();
        Charset charset3 = Charsets.d;
        if (charset3 != null) {
            return charset3;
        }
        Charset charsetForName2 = Charset.forName("UTF-32LE");
        Intrinsics.checkNotNullExpressionValue(charsetForName2, "forName(...)");
        Charsets.d = charsetForName2;
        return charsetForName2;
    }

    public static final int u(okio.A a2) {
        Intrinsics.checkNotNullParameter(a2, "<this>");
        return (a2.readByte() & 255) | ((a2.readByte() & 255) << 16) | ((a2.readByte() & 255) << 8);
    }

    public static final boolean v(G g2, int i) {
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        Intrinsics.checkNotNullParameter(g2, "<this>");
        Intrinsics.checkNotNullParameter(timeUnit, "timeUnit");
        long jNanoTime = System.nanoTime();
        long jC = g2.h().e() ? g2.h().c() - jNanoTime : Long.MAX_VALUE;
        g2.h().d(Math.min(jC, timeUnit.toNanos(i)) + jNanoTime);
        try {
            C5091h c5091h = new C5091h();
            while (g2.b0(c5091h, 8192L) != -1) {
                c5091h.d();
            }
            if (jC == Long.MAX_VALUE) {
                g2.h().a();
                return true;
            }
            g2.h().d(jNanoTime + jC);
            return true;
        } catch (InterruptedIOException unused) {
            if (jC == Long.MAX_VALUE) {
                g2.h().a();
                return false;
            }
            g2.h().d(jNanoTime + jC);
            return false;
        } catch (Throwable th) {
            if (jC == Long.MAX_VALUE) {
                g2.h().a();
            } else {
                g2.h().d(jNanoTime + jC);
            }
            throw th;
        }
    }

    public static final r w(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        ArrayList arrayList = new ArrayList(20);
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            okhttp3.internal.http2.b bVar = (okhttp3.internal.http2.b) it2.next();
            String name = bVar.a.s();
            String value = bVar.b.s();
            Intrinsics.checkNotNullParameter(name, "name");
            Intrinsics.checkNotNullParameter(value, "value");
            arrayList.add(name);
            arrayList.add(StringsKt.g0(value).toString());
        }
        return new r((String[]) arrayList.toArray(new String[0]));
    }

    public static final String x(s sVar, boolean z) {
        Intrinsics.checkNotNullParameter(sVar, "<this>");
        boolean zG = StringsKt.G(sVar.d, ":", false);
        String strH = sVar.d;
        if (zG) {
            strH = androidx.compose.ui.node.B.h("[", strH, ']');
        }
        int i = sVar.e;
        if (!z) {
            String scheme = sVar.a;
            Intrinsics.checkNotNullParameter(scheme, "scheme");
            if (i == (Intrinsics.b(scheme, "http") ? 80 : Intrinsics.b(scheme, "https") ? 443 : -1)) {
                return strH;
            }
        }
        return strH + ':' + i;
    }

    public static final List y(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        List listUnmodifiableList = Collections.unmodifiableList(CollectionsKt.y0(list));
        Intrinsics.checkNotNullExpressionValue(listUnmodifiableList, "unmodifiableList(toMutableList())");
        return listUnmodifiableList;
    }

    public static final int z(int i, String str) throws NumberFormatException {
        if (str == null) {
            return i;
        }
        try {
            long j = Long.parseLong(str);
            if (j > 2147483647L) {
                return SubsamplingScaleImageView.TILE_SIZE_AUTO;
            }
            if (j < 0) {
                return 0;
            }
            return (int) j;
        } catch (NumberFormatException unused) {
            return i;
        }
    }
}
