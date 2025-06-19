package coil3.disk;

import androidx.compose.ui.node.B;
import androidx.navigation.U;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3485l;
import java.io.EOFException;
import java.io.IOException;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.C4937f;
import kotlin.Unit;
import kotlin.coroutines.k;
import kotlin.coroutines.n;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import kotlinx.coroutines.A0;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;
import okio.A;
import okio.AbstractC5085b;
import okio.t;
import okio.x;
import okio.z;

/* loaded from: classes.dex */
public final class e implements AutoCloseable {
    public static final Regex r = new Regex("[a-z0-9_-]{1,120}");
    public final x a;
    public final long b;
    public final x c;
    public final x d;
    public final x e;
    public final LinkedHashMap f;
    public final kotlinx.coroutines.internal.d g;
    public final Object h;
    public long i;
    public int j;
    public z k;
    public boolean l;
    public boolean m;
    public boolean n;
    public boolean o;
    public boolean p;
    public final c q;

    public e(long j, n nVar, t tVar, x xVar) {
        this.a = xVar;
        this.b = j;
        if (j <= 0) {
            throw new IllegalArgumentException("maxSize <= 0");
        }
        this.c = xVar.e("journal");
        this.d = xVar.e("journal.tmp");
        this.e = xVar.e("journal.bkp");
        this.f = new LinkedHashMap(0, 0.75f, true);
        A0 context = E.e();
        nVar.getClass();
        Intrinsics.checkNotNullParameter(context, "context");
        nVar.get(AbstractC5040y.a);
        kotlinx.coroutines.scheduling.e eVar = O.a;
        this.g = E.c(k.c(kotlinx.coroutines.scheduling.d.b.c0(1), context));
        this.h = new Object();
        this.q = new c(tVar);
    }

    public static void C(String str) {
        if (!r.e(str)) {
            throw new IllegalArgumentException(B.h("keys must match regex [a-z0-9_-]{1,120}: \"", str, '\"').toString());
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:58:0x0110 A[Catch: all -> 0x0038, TryCatch #0 {, blocks: (B:4:0x0004, B:8:0x0014, B:12:0x001b, B:14:0x0023, B:16:0x0033, B:24:0x0040, B:26:0x0058, B:28:0x006b, B:30:0x007b, B:32:0x0082, B:27:0x005e, B:36:0x00a0, B:38:0x00a7, B:41:0x00ac, B:43:0x00bc, B:46:0x00c1, B:51:0x00fb, B:53:0x0106, B:59:0x0113, B:58:0x0110, B:47:0x00d9, B:49:0x00ee, B:50:0x00f8, B:35:0x0091, B:62:0x0117, B:63:0x011e), top: B:66:0x0004 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(coil3.disk.e r11, androidx.browser.customtabs.k r12, boolean r13) {
        /*
            Method dump skipped, instructions count: 289
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.disk.e.a(coil3.disk.e, androidx.browser.customtabs.k, boolean):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:9:0x0022, code lost:
    
        y(r1);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void B() {
        /*
            r4 = this;
        L0:
            long r0 = r4.i
            long r2 = r4.b
            int r0 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r0 <= 0) goto L27
            java.util.LinkedHashMap r0 = r4.f
            java.util.Collection r0 = r0.values()
            java.util.Iterator r0 = r0.iterator()
        L12:
            boolean r1 = r0.hasNext()
            if (r1 == 0) goto L26
            java.lang.Object r1 = r0.next()
            coil3.disk.a r1 = (coil3.disk.a) r1
            boolean r2 = r1.f
            if (r2 != 0) goto L12
            r4.y(r1)
            goto L0
        L26:
            return
        L27:
            r0 = 0
            r4.o = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.disk.e.B():void");
    }

    public final void D() {
        Throwable th;
        synchronized (this.h) {
            try {
                z zVar = this.k;
                if (zVar != null) {
                    zVar.close();
                }
                z zVarB = AbstractC5085b.b(this.q.D(this.d, false));
                try {
                    zVarB.H("libcore.io.DiskLruCache");
                    zVarB.v(10);
                    zVarB.H("1");
                    zVarB.v(10);
                    zVarB.h0(3);
                    zVarB.v(10);
                    zVarB.h0(2);
                    zVarB.v(10);
                    zVarB.v(10);
                    for (a aVar : this.f.values()) {
                        if (aVar.g != null) {
                            zVarB.H("DIRTY");
                            zVarB.v(32);
                            zVarB.H(aVar.a);
                            zVarB.v(10);
                        } else {
                            zVarB.H("CLEAN");
                            zVarB.v(32);
                            zVarB.H(aVar.a);
                            for (long j : aVar.b) {
                                zVarB.v(32);
                                zVarB.h0(j);
                            }
                            zVarB.v(10);
                        }
                    }
                    Unit unit = Unit.a;
                    try {
                        zVarB.close();
                        th = null;
                    } catch (Throwable th2) {
                        th = th2;
                    }
                } catch (Throwable th3) {
                    try {
                        zVarB.close();
                    } catch (Throwable th4) {
                        C4937f.a(th3, th4);
                    }
                    th = th3;
                }
                if (th != null) {
                    throw th;
                }
                if (this.q.p(this.c)) {
                    this.q.d(this.c, this.e);
                    this.q.d(this.d, this.c);
                    this.q.j(this.e);
                } else {
                    this.q.d(this.d, this.c);
                }
                this.k = l();
                this.j = 0;
                this.l = false;
                this.p = false;
                Unit unit2 = Unit.a;
            } catch (Throwable th5) {
                throw th5;
            }
        }
    }

    @Override // java.lang.AutoCloseable
    public final void close() {
        synchronized (this.h) {
            try {
                if (this.m && !this.n) {
                    for (a aVar : (a[]) this.f.values().toArray(new a[0])) {
                        androidx.browser.customtabs.k kVar = aVar.g;
                        if (kVar != null) {
                            a aVar2 = (a) kVar.b;
                            if (Intrinsics.b(aVar2.g, kVar)) {
                                aVar2.f = true;
                            }
                        }
                    }
                    B();
                    E.i(this.g, null);
                    z zVar = this.k;
                    Intrinsics.d(zVar);
                    zVar.close();
                    this.k = null;
                    this.n = true;
                    Unit unit = Unit.a;
                    return;
                }
                this.n = true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final androidx.browser.customtabs.k d(String str) {
        synchronized (this.h) {
            try {
                if (this.n) {
                    throw new IllegalStateException("cache is closed");
                }
                C(str);
                i();
                a aVar = (a) this.f.get(str);
                if ((aVar != null ? aVar.g : null) != null) {
                    return null;
                }
                if (aVar != null && aVar.h != 0) {
                    return null;
                }
                if (!this.o && !this.p) {
                    z zVar = this.k;
                    Intrinsics.d(zVar);
                    zVar.H("DIRTY");
                    zVar.v(32);
                    zVar.H(str);
                    zVar.v(10);
                    zVar.flush();
                    if (this.l) {
                        return null;
                    }
                    if (aVar == null) {
                        aVar = new a(this, str);
                        this.f.put(str, aVar);
                    }
                    androidx.browser.customtabs.k kVar = new androidx.browser.customtabs.k(this, aVar);
                    aVar.g = kVar;
                    return kVar;
                }
                j();
                return null;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final b f(String str) {
        b bVarA;
        synchronized (this.h) {
            if (this.n) {
                throw new IllegalStateException("cache is closed");
            }
            C(str);
            i();
            a aVar = (a) this.f.get(str);
            if (aVar != null && (bVarA = aVar.a()) != null) {
                boolean z = true;
                this.j++;
                z zVar = this.k;
                Intrinsics.d(zVar);
                zVar.H("READ");
                zVar.v(32);
                zVar.H(str);
                zVar.v(10);
                zVar.flush();
                if (this.j < 2000) {
                    z = false;
                }
                if (z) {
                    j();
                }
                return bVarA;
            }
            return null;
        }
    }

    public final void i() {
        synchronized (this.h) {
            try {
                if (this.m) {
                    return;
                }
                this.q.j(this.d);
                if (this.q.p(this.e)) {
                    if (this.q.p(this.c)) {
                        this.q.j(this.e);
                    } else {
                        this.q.d(this.e, this.c);
                    }
                }
                if (this.q.p(this.c)) {
                    try {
                        q();
                        p();
                        this.m = true;
                        return;
                    } catch (IOException unused) {
                        try {
                            close();
                            AbstractC3485l.c(this.q, this.a);
                            this.n = false;
                        } catch (Throwable th) {
                            this.n = false;
                            throw th;
                        }
                    }
                }
                D();
                this.m = true;
                Unit unit = Unit.a;
            } catch (Throwable th2) {
                throw th2;
            }
        }
    }

    public final void j() {
        E.A(this.g, null, null, new d(this, null), 3);
    }

    public final z l() {
        c cVar = this.q;
        cVar.getClass();
        x file = this.c;
        Intrinsics.checkNotNullParameter(file, "file");
        return AbstractC5085b.b(new f(cVar.a(file, false), new U(this, 2)));
    }

    public final void p() {
        Iterator it2 = this.f.values().iterator();
        long j = 0;
        while (it2.hasNext()) {
            a aVar = (a) it2.next();
            int i = 0;
            if (aVar.g == null) {
                while (i < 2) {
                    j += aVar.b[i];
                    i++;
                }
            } else {
                aVar.g = null;
                while (i < 2) {
                    x xVar = (x) aVar.c.get(i);
                    c cVar = this.q;
                    cVar.j(xVar);
                    cVar.j((x) aVar.d.get(i));
                    i++;
                }
                it2.remove();
            }
        }
        this.i = j;
    }

    public final void q() throws Throwable {
        A aC = AbstractC5085b.c(this.q.P(this.c));
        try {
            String strY = aC.y(Long.MAX_VALUE);
            String strY2 = aC.y(Long.MAX_VALUE);
            String strY3 = aC.y(Long.MAX_VALUE);
            String strY4 = aC.y(Long.MAX_VALUE);
            String strY5 = aC.y(Long.MAX_VALUE);
            if (!"libcore.io.DiskLruCache".equals(strY) || !"1".equals(strY2) || !Intrinsics.b(String.valueOf(3), strY3) || !Intrinsics.b(String.valueOf(2), strY4) || strY5.length() > 0) {
                throw new IOException("unexpected journal header: [" + strY + ", " + strY2 + ", " + strY3 + ", " + strY4 + ", " + strY5 + ']');
            }
            int i = 0;
            while (true) {
                try {
                    r(aC.y(Long.MAX_VALUE));
                    i++;
                } catch (EOFException unused) {
                    this.j = i - this.f.size();
                    if (aC.u()) {
                        this.k = l();
                    } else {
                        D();
                    }
                    Unit unit = Unit.a;
                    try {
                        aC.close();
                        th = null;
                    } catch (Throwable th) {
                        th = th;
                    }
                    if (th != null) {
                        throw th;
                    }
                    return;
                }
            }
        } catch (Throwable th2) {
            th = th2;
            try {
                aC.close();
            } catch (Throwable th3) {
                C4937f.a(th, th3);
            }
        }
    }

    public final void r(String str) throws IOException {
        String strSubstring;
        int iL = StringsKt.L(str, ' ', 0, false, 6);
        if (iL == -1) {
            throw new IOException("unexpected journal line: ".concat(str));
        }
        int i = iL + 1;
        int iL2 = StringsKt.L(str, ' ', i, false, 4);
        LinkedHashMap linkedHashMap = this.f;
        if (iL2 == -1) {
            strSubstring = str.substring(i);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
            if (iL == 6 && D.r(str, "REMOVE", false)) {
                linkedHashMap.remove(strSubstring);
                return;
            }
        } else {
            strSubstring = str.substring(i, iL2);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        }
        Object aVar = linkedHashMap.get(strSubstring);
        if (aVar == null) {
            aVar = new a(this, strSubstring);
            linkedHashMap.put(strSubstring, aVar);
        }
        a aVar2 = (a) aVar;
        if (iL2 == -1 || iL != 5 || !D.r(str, "CLEAN", false)) {
            if (iL2 == -1 && iL == 5 && D.r(str, "DIRTY", false)) {
                aVar2.g = new androidx.browser.customtabs.k(this, aVar2);
                return;
            } else {
                if (iL2 != -1 || iL != 4 || !D.r(str, "READ", false)) {
                    throw new IOException("unexpected journal line: ".concat(str));
                }
                return;
            }
        }
        String strSubstring2 = str.substring(iL2 + 1);
        Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
        List listV = StringsKt.V(strSubstring2, new char[]{' '});
        aVar2.e = true;
        aVar2.g = null;
        int size = listV.size();
        aVar2.i.getClass();
        if (size != 2) {
            throw new IOException("unexpected journal line: " + listV);
        }
        try {
            int size2 = listV.size();
            for (int i2 = 0; i2 < size2; i2++) {
                aVar2.b[i2] = Long.parseLong((String) listV.get(i2));
            }
        } catch (NumberFormatException unused) {
            throw new IOException("unexpected journal line: " + listV);
        }
    }

    public final void y(a aVar) {
        z zVar;
        int i = aVar.h;
        String str = aVar.a;
        if (i > 0 && (zVar = this.k) != null) {
            zVar.H("DIRTY");
            zVar.v(32);
            zVar.H(str);
            zVar.v(10);
            zVar.flush();
        }
        if (aVar.h > 0 || aVar.g != null) {
            aVar.f = true;
            return;
        }
        for (int i2 = 0; i2 < 2; i2++) {
            this.q.j((x) aVar.c.get(i2));
            long j = this.i;
            long[] jArr = aVar.b;
            this.i = j - jArr[i2];
            jArr[i2] = 0;
        }
        this.j++;
        z zVar2 = this.k;
        if (zVar2 != null) {
            zVar2.H("REMOVE");
            zVar2.v(32);
            zVar2.H(str);
            zVar2.v(10);
            zVar2.flush();
        }
        this.f.remove(str);
        if (this.j >= 2000) {
            j();
        }
    }
}
