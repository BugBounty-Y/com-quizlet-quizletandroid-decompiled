package com.google.android.gms.internal.ads;

import java.net.UnknownServiceException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.net.ssl.SSLSocket;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.C5080i;
import okhttp3.C5081j;
import okhttp3.C5082k;

/* renamed from: com.google.android.gms.internal.ads.Ka, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1719Ka implements com.google.android.gms.ads.mediation.d {
    public int a;
    public boolean b;
    public boolean c;
    public final Object d;

    public C1719Ka(com.google.android.gms.measurement.internal.I i, int i2, boolean z, boolean z2) {
        this.d = i;
        this.a = i2;
        this.b = z;
        this.c = z2;
    }

    @Override // com.google.android.gms.ads.mediation.d
    public int a() {
        return this.a;
    }

    @Override // com.google.android.gms.ads.mediation.d
    public boolean b() {
        return this.c;
    }

    @Override // com.google.android.gms.ads.mediation.d
    public boolean c() {
        return this.b;
    }

    @Override // com.google.android.gms.ads.mediation.d
    public Set d() {
        return (HashSet) this.d;
    }

    public C5082k e(SSLSocket sslSocket) throws UnknownServiceException {
        C5082k connectionSpec;
        int i;
        boolean z;
        String[] cipherSuitesIntersection;
        String[] tlsVersionsIntersection;
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        int i2 = this.a;
        List list = (List) this.d;
        int size = list.size();
        while (true) {
            if (i2 >= size) {
                connectionSpec = null;
                break;
            }
            connectionSpec = (C5082k) list.get(i2);
            if (connectionSpec.b(sslSocket)) {
                this.a = i2 + 1;
                break;
            }
            i2++;
        }
        if (connectionSpec == null) {
            StringBuilder sb = new StringBuilder("Unable to find acceptable protocols. isFallback=");
            sb.append(this.c);
            sb.append(", modes=");
            sb.append(list);
            sb.append(", supported protocols=");
            String[] enabledProtocols = sslSocket.getEnabledProtocols();
            Intrinsics.d(enabledProtocols);
            String string = Arrays.toString(enabledProtocols);
            Intrinsics.checkNotNullExpressionValue(string, "toString(this)");
            sb.append(string);
            throw new UnknownServiceException(sb.toString());
        }
        int i3 = this.a;
        int size2 = list.size();
        while (true) {
            i = 0;
            if (i3 >= size2) {
                z = false;
                break;
            }
            if (((C5082k) list.get(i3)).b(sslSocket)) {
                z = true;
                break;
            }
            i3++;
        }
        this.b = z;
        boolean z2 = this.c;
        Intrinsics.checkNotNullParameter(sslSocket, "sslSocket");
        String[] strArr = connectionSpec.c;
        if (strArr != null) {
            String[] enabledCipherSuites = sslSocket.getEnabledCipherSuites();
            Intrinsics.checkNotNullExpressionValue(enabledCipherSuites, "sslSocket.enabledCipherSuites");
            cipherSuitesIntersection = okhttp3.internal.b.q(enabledCipherSuites, strArr, C5081j.c);
        } else {
            cipherSuitesIntersection = sslSocket.getEnabledCipherSuites();
        }
        String[] strArr2 = connectionSpec.d;
        if (strArr2 != null) {
            String[] enabledProtocols2 = sslSocket.getEnabledProtocols();
            Intrinsics.checkNotNullExpressionValue(enabledProtocols2, "sslSocket.enabledProtocols");
            kotlin.comparisons.b bVar = kotlin.comparisons.b.a;
            Intrinsics.e(bVar, "null cannot be cast to non-null type java.util.Comparator<T of kotlin.comparisons.ComparisonsKt__ComparisonsKt.naturalOrder>{ kotlin.TypeAliasesKt.Comparator<T of kotlin.comparisons.ComparisonsKt__ComparisonsKt.naturalOrder> }");
            tlsVersionsIntersection = okhttp3.internal.b.q(enabledProtocols2, strArr2, bVar);
        } else {
            tlsVersionsIntersection = sslSocket.getEnabledProtocols();
        }
        String[] supportedCipherSuites = sslSocket.getSupportedCipherSuites();
        Intrinsics.checkNotNullExpressionValue(supportedCipherSuites, "supportedCipherSuites");
        C5080i comparator = C5081j.c;
        byte[] bArr = okhttp3.internal.b.a;
        Intrinsics.checkNotNullParameter(supportedCipherSuites, "<this>");
        Intrinsics.checkNotNullParameter("TLS_FALLBACK_SCSV", "value");
        Intrinsics.checkNotNullParameter(comparator, "comparator");
        int length = supportedCipherSuites.length;
        while (true) {
            if (i >= length) {
                i = -1;
                break;
            }
            if (comparator.compare(supportedCipherSuites[i], "TLS_FALLBACK_SCSV") == 0) {
                break;
            }
            i++;
        }
        if (z2 && i != -1) {
            Intrinsics.checkNotNullExpressionValue(cipherSuitesIntersection, "cipherSuitesIntersection");
            String value = supportedCipherSuites[i];
            Intrinsics.checkNotNullExpressionValue(value, "supportedCipherSuites[indexOfFallbackScsv]");
            Intrinsics.checkNotNullParameter(cipherSuitesIntersection, "<this>");
            Intrinsics.checkNotNullParameter(value, "value");
            Object[] objArrCopyOf = Arrays.copyOf(cipherSuitesIntersection, cipherSuitesIntersection.length + 1);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(this, newSize)");
            cipherSuitesIntersection = (String[]) objArrCopyOf;
            cipherSuitesIntersection[C4933y.E(cipherSuitesIntersection)] = value;
        }
        Intrinsics.checkNotNullParameter(connectionSpec, "connectionSpec");
        androidx.appcompat.widget.o1 o1Var = new androidx.appcompat.widget.o1();
        o1Var.a = connectionSpec.a;
        o1Var.c = strArr;
        o1Var.d = strArr2;
        o1Var.b = connectionSpec.b;
        Intrinsics.checkNotNullExpressionValue(cipherSuitesIntersection, "cipherSuitesIntersection");
        o1Var.c((String[]) Arrays.copyOf(cipherSuitesIntersection, cipherSuitesIntersection.length));
        Intrinsics.checkNotNullExpressionValue(tlsVersionsIntersection, "tlsVersionsIntersection");
        o1Var.e((String[]) Arrays.copyOf(tlsVersionsIntersection, tlsVersionsIntersection.length));
        C5082k c5082kB = o1Var.b();
        if (c5082kB.c() != null) {
            sslSocket.setEnabledProtocols(c5082kB.d);
        }
        if (c5082kB.a() != null) {
            sslSocket.setEnabledCipherSuites(c5082kB.c);
        }
        return connectionSpec;
    }

    public void f(String str) {
        ((com.google.android.gms.measurement.internal.I) this.d).e0(this.a, this.b, this.c, str, null, null, null);
    }

    public void g(String str, Object obj) {
        ((com.google.android.gms.measurement.internal.I) this.d).e0(this.a, this.b, this.c, str, obj, null, null);
    }

    public void h(String str, Object obj, Object obj2) {
        ((com.google.android.gms.measurement.internal.I) this.d).e0(this.a, this.b, this.c, str, obj, obj2, null);
    }

    public void i(String str, Object obj, Object obj2, Object obj3) {
        ((com.google.android.gms.measurement.internal.I) this.d).e0(this.a, this.b, this.c, str, obj, obj2, obj3);
    }

    public C1719Ka(HashSet hashSet, boolean z, int i, boolean z2) {
        this.d = hashSet;
        this.b = z;
        this.a = i;
        this.c = z2;
    }

    public C1719Ka(List connectionSpecs) {
        Intrinsics.checkNotNullParameter(connectionSpecs, "connectionSpecs");
        this.d = connectionSpecs;
    }
}
