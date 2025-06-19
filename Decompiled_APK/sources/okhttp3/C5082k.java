package okhttp3;

import androidx.appcompat.widget.o1;
import androidx.transition.C1413p;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.net.ssl.SSLSocket;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: okhttp3.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5082k {
    public static final C5082k e;
    public static final C5082k f;
    public final boolean a;
    public final boolean b;
    public final String[] c;
    public final String[] d;

    static {
        C5081j c5081j = C5081j.r;
        C5081j c5081j2 = C5081j.s;
        C5081j c5081j3 = C5081j.t;
        C5081j c5081j4 = C5081j.l;
        C5081j c5081j5 = C5081j.n;
        C5081j c5081j6 = C5081j.m;
        C5081j c5081j7 = C5081j.o;
        C5081j c5081j8 = C5081j.q;
        C5081j c5081j9 = C5081j.p;
        C5081j[] c5081jArr = {c5081j, c5081j2, c5081j3, c5081j4, c5081j5, c5081j6, c5081j7, c5081j8, c5081j9};
        C5081j[] c5081jArr2 = {c5081j, c5081j2, c5081j3, c5081j4, c5081j5, c5081j6, c5081j7, c5081j8, c5081j9, C5081j.j, C5081j.k, C5081j.h, C5081j.i, C5081j.f, C5081j.g, C5081j.e};
        o1 o1Var = new o1();
        o1Var.d((C5081j[]) Arrays.copyOf(c5081jArr, 9));
        L l = L.TLS_1_3;
        L l2 = L.TLS_1_2;
        o1Var.f(l, l2);
        if (!o1Var.a) {
            throw new IllegalArgumentException("no TLS extensions for cleartext connections");
        }
        o1Var.b = true;
        o1Var.b();
        o1 o1Var2 = new o1();
        o1Var2.d((C5081j[]) Arrays.copyOf(c5081jArr2, 16));
        o1Var2.f(l, l2);
        if (!o1Var2.a) {
            throw new IllegalArgumentException("no TLS extensions for cleartext connections");
        }
        o1Var2.b = true;
        e = o1Var2.b();
        o1 o1Var3 = new o1();
        o1Var3.d((C5081j[]) Arrays.copyOf(c5081jArr2, 16));
        o1Var3.f(l, l2, L.TLS_1_1, L.TLS_1_0);
        if (!o1Var3.a) {
            throw new IllegalArgumentException("no TLS extensions for cleartext connections");
        }
        o1Var3.b = true;
        o1Var3.b();
        f = new C5082k(false, false, null, null);
    }

    public C5082k(boolean z, boolean z2, String[] strArr, String[] strArr2) {
        this.a = z;
        this.b = z2;
        this.c = strArr;
        this.d = strArr2;
    }

    public final List a() {
        String[] strArr = this.c;
        if (strArr == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList(strArr.length);
        for (String str : strArr) {
            arrayList.add(C5081j.b.d(str));
        }
        return CollectionsKt.w0(arrayList);
    }

    public final boolean b(SSLSocket socket) {
        Intrinsics.checkNotNullParameter(socket, "socket");
        if (!this.a) {
            return false;
        }
        String[] strArr = this.d;
        if (strArr != null) {
            String[] enabledProtocols = socket.getEnabledProtocols();
            kotlin.comparisons.b bVar = kotlin.comparisons.b.a;
            Intrinsics.e(bVar, "null cannot be cast to non-null type java.util.Comparator<T of kotlin.comparisons.ComparisonsKt__ComparisonsKt.naturalOrder>{ kotlin.TypeAliasesKt.Comparator<T of kotlin.comparisons.ComparisonsKt__ComparisonsKt.naturalOrder> }");
            if (!okhttp3.internal.b.k(strArr, enabledProtocols, bVar)) {
                return false;
            }
        }
        String[] strArr2 = this.c;
        return strArr2 == null || okhttp3.internal.b.k(strArr2, socket.getEnabledCipherSuites(), C5081j.c);
    }

    public final List c() {
        String[] strArr = this.d;
        if (strArr == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList(strArr.length);
        for (String str : strArr) {
            arrayList.add(C1413p.i(str));
        }
        return CollectionsKt.w0(arrayList);
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C5082k)) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        C5082k c5082k = (C5082k) obj;
        boolean z = c5082k.a;
        boolean z2 = this.a;
        if (z2 != z) {
            return false;
        }
        if (z2) {
            return Arrays.equals(this.c, c5082k.c) && Arrays.equals(this.d, c5082k.d) && this.b == c5082k.b;
        }
        return true;
    }

    public final int hashCode() {
        if (!this.a) {
            return 17;
        }
        String[] strArr = this.c;
        int iHashCode = (527 + (strArr != null ? Arrays.hashCode(strArr) : 0)) * 31;
        String[] strArr2 = this.d;
        return ((iHashCode + (strArr2 != null ? Arrays.hashCode(strArr2) : 0)) * 31) + (!this.b ? 1 : 0);
    }

    public final String toString() {
        if (!this.a) {
            return "ConnectionSpec()";
        }
        StringBuilder sb = new StringBuilder("ConnectionSpec(cipherSuites=");
        sb.append(Objects.toString(a(), "[all enabled]"));
        sb.append(", tlsVersions=");
        sb.append(Objects.toString(c(), "[all enabled]"));
        sb.append(", supportsTlsExtensions=");
        return android.support.v4.media.session.a.u(sb, this.b, ')');
    }
}
