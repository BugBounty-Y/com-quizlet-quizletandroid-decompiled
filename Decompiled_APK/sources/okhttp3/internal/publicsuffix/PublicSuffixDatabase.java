package okhttp3.internal.publicsuffix;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.IDN;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlin.sequences.Sequence;
import kotlin.sequences.b;
import kotlin.sequences.c;
import kotlin.sequences.q;
import kotlin.text.StringsKt;
import okhttp3.internal.platform.o;
import okio.AbstractC5085b;

@Metadata
/* loaded from: classes3.dex */
public final class PublicSuffixDatabase {
    public static final byte[] e = {42};
    public static final List f = A.b("*");
    public static final PublicSuffixDatabase g = new PublicSuffixDatabase();
    public final AtomicBoolean a = new AtomicBoolean(false);
    public final CountDownLatch b = new CountDownLatch(1);
    public byte[] c;
    public byte[] d;

    public static List c(String str) {
        List listV = StringsKt.V(str, new char[]{'.'});
        return Intrinsics.b(CollectionsKt.U(listV), "") ? CollectionsKt.I(1, listV) : listV;
    }

    public final String a(String domain) throws InterruptedException {
        String strA;
        String strA2;
        String strA3;
        List listV;
        List listV2;
        Intrinsics.checkNotNullParameter(domain, "domain");
        String unicodeDomain = IDN.toUnicode(domain);
        Intrinsics.checkNotNullExpressionValue(unicodeDomain, "unicodeDomain");
        List listC = c(unicodeDomain);
        if (this.a.get() || !this.a.compareAndSet(false, true)) {
            try {
                this.b.await();
            } catch (InterruptedException unused) {
                Thread.currentThread().interrupt();
            }
        } else {
            boolean z = false;
            while (true) {
                try {
                    try {
                        b();
                        break;
                    } finally {
                        if (z) {
                            Thread.currentThread().interrupt();
                        }
                    }
                } catch (InterruptedIOException unused2) {
                    Thread.interrupted();
                    z = true;
                } catch (IOException e2) {
                    o oVar = o.a;
                    o.a.getClass();
                    o.i(5, "Failed to read public suffix list", e2);
                    if (z) {
                    }
                }
            }
        }
        if (this.c == null) {
            throw new IllegalStateException("Unable to load publicsuffixes.gz resource from the classpath.");
        }
        int size = listC.size();
        byte[][] bArr = new byte[size][];
        for (int i = 0; i < size; i++) {
            String str = (String) listC.get(i);
            Charset UTF_8 = StandardCharsets.UTF_8;
            Intrinsics.checkNotNullExpressionValue(UTF_8, "UTF_8");
            byte[] bytes = str.getBytes(UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            bArr[i] = bytes;
        }
        int i2 = 0;
        while (true) {
            if (i2 >= size) {
                strA = null;
                break;
            }
            byte[] bArr2 = this.c;
            if (bArr2 == null) {
                Intrinsics.m("publicSuffixListBytes");
                throw null;
            }
            strA = a.a(bArr2, bArr, i2);
            if (strA != null) {
                break;
            }
            i2++;
        }
        if (size > 1) {
            byte[][] bArr3 = (byte[][]) bArr.clone();
            int length = bArr3.length - 1;
            for (int i3 = 0; i3 < length; i3++) {
                bArr3[i3] = e;
                byte[] bArr4 = this.c;
                if (bArr4 == null) {
                    Intrinsics.m("publicSuffixListBytes");
                    throw null;
                }
                strA2 = a.a(bArr4, bArr3, i3);
                if (strA2 != null) {
                    break;
                }
            }
            strA2 = null;
        } else {
            strA2 = null;
        }
        if (strA2 != null) {
            int i4 = size - 1;
            for (int i5 = 0; i5 < i4; i5++) {
                byte[] bArr5 = this.d;
                if (bArr5 == null) {
                    Intrinsics.m("publicSuffixExceptionListBytes");
                    throw null;
                }
                strA3 = a.a(bArr5, bArr, i5);
                if (strA3 != null) {
                    break;
                }
            }
            strA3 = null;
        } else {
            strA3 = null;
        }
        if (strA3 != null) {
            listV2 = StringsKt.V("!".concat(strA3), new char[]{'.'});
        } else if (strA == null && strA2 == null) {
            listV2 = f;
        } else {
            if (strA == null || (listV = StringsKt.V(strA, new char[]{'.'})) == null) {
                listV = K.a;
            }
            if (strA2 == null || (listV2 = StringsKt.V(strA2, new char[]{'.'})) == null) {
                listV2 = K.a;
            }
            if (listV.size() > listV2.size()) {
                listV2 = listV;
            }
        }
        if (listC.size() == listV2.size() && ((String) listV2.get(0)).charAt(0) != '!') {
            return null;
        }
        int size2 = ((String) listV2.get(0)).charAt(0) == '!' ? listC.size() - listV2.size() : listC.size() - (listV2.size() + 1);
        Sequence sequenceD = CollectionsKt.D(c(domain));
        Intrinsics.checkNotNullParameter(sequenceD, "<this>");
        if (size2 < 0) {
            throw new IllegalArgumentException(AbstractC0147y.c(size2, "Requested element count ", " is less than zero.").toString());
        }
        if (size2 != 0) {
            sequenceD = sequenceD instanceof c ? ((c) sequenceD).a(size2) : new b(sequenceD, size2);
        }
        return q.g(sequenceD, ".");
    }

    public final void b() {
        try {
            J j = new J();
            J j2 = new J();
            InputStream resourceAsStream = PublicSuffixDatabase.class.getResourceAsStream("publicsuffixes.gz");
            if (resourceAsStream != null) {
                okio.A aC = AbstractC5085b.c(new okio.q(AbstractC5085b.j(resourceAsStream)));
                try {
                    long jI = aC.i();
                    aC.k(jI);
                    j.a = aC.b.B(jI);
                    long jI2 = aC.i();
                    aC.k(jI2);
                    j2.a = aC.b.B(jI2);
                    Unit unit = Unit.a;
                    aC.close();
                    synchronized (this) {
                        Object obj = j.a;
                        Intrinsics.d(obj);
                        this.c = (byte[]) obj;
                        Object obj2 = j2.a;
                        Intrinsics.d(obj2);
                        this.d = (byte[]) obj2;
                    }
                } finally {
                }
            }
        } finally {
            this.b.countDown();
        }
    }
}
