package androidx.compose.ui.text.caches;

import androidx.compose.animation.core.U0;
import com.google.android.gms.internal.mlkit_common.u;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import kotlin.Unit;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.internal.http2.d;
import okhttp3.internal.http2.q;
import okhttp3.internal.http2.x;
import okio.A;
import okio.AbstractC5085b;
import okio.C5091h;
import okio.k;

/* loaded from: classes.dex */
public final class b {
    public final /* synthetic */ int a;
    public int b;
    public int c;
    public int d;
    public int e;
    public final Object f;
    public final Object g;
    public Object h;

    public b(q source) {
        this.a = 1;
        Intrinsics.checkNotNullParameter(source, "source");
        this.b = 4096;
        this.f = new ArrayList();
        this.g = AbstractC5085b.c(source);
        this.h = new okhttp3.internal.http2.b[8];
        this.c = 7;
    }

    public int a(int i) {
        int i2;
        int i3 = 0;
        if (i > 0) {
            int length = ((okhttp3.internal.http2.b[]) this.h).length;
            while (true) {
                length--;
                i2 = this.c;
                if (length < i2 || i <= 0) {
                    break;
                }
                okhttp3.internal.http2.b bVar = ((okhttp3.internal.http2.b[]) this.h)[length];
                Intrinsics.d(bVar);
                int i4 = bVar.c;
                i -= i4;
                this.e -= i4;
                this.d--;
                i3++;
            }
            okhttp3.internal.http2.b[] bVarArr = (okhttp3.internal.http2.b[]) this.h;
            System.arraycopy(bVarArr, i2 + 1, bVarArr, i2 + 1 + i3, this.d);
            this.c += i3;
        }
        return i3;
    }

    public Object b(Object obj) {
        synchronized (((u) this.f)) {
            Object obj2 = ((HashMap) this.g).get(obj);
            if (obj2 == null) {
                this.e++;
                return null;
            }
            ((LinkedHashSet) this.h).remove(obj);
            ((LinkedHashSet) this.h).add(obj);
            this.d++;
            return obj2;
        }
    }

    public k c(int i) throws IOException {
        if (i >= 0) {
            okhttp3.internal.http2.b[] bVarArr = d.a;
            if (i <= bVarArr.length - 1) {
                return bVarArr[i].a;
            }
        }
        int length = this.c + 1 + (i - d.a.length);
        if (length >= 0) {
            okhttp3.internal.http2.b[] bVarArr2 = (okhttp3.internal.http2.b[]) this.h;
            if (length < bVarArr2.length) {
                okhttp3.internal.http2.b bVar = bVarArr2[length];
                Intrinsics.d(bVar);
                return bVar.a;
            }
        }
        throw new IOException("Header index too large " + (i + 1));
    }

    public void d(okhttp3.internal.http2.b bVar) {
        ((ArrayList) this.f).add(bVar);
        int i = this.b;
        int i2 = bVar.c;
        if (i2 > i) {
            okhttp3.internal.http2.b[] bVarArr = (okhttp3.internal.http2.b[]) this.h;
            C4930v.o(bVarArr, null, 0, bVarArr.length);
            this.c = ((okhttp3.internal.http2.b[]) this.h).length - 1;
            this.d = 0;
            this.e = 0;
            return;
        }
        a((this.e + i2) - i);
        int i3 = this.d + 1;
        okhttp3.internal.http2.b[] bVarArr2 = (okhttp3.internal.http2.b[]) this.h;
        if (i3 > bVarArr2.length) {
            okhttp3.internal.http2.b[] bVarArr3 = new okhttp3.internal.http2.b[bVarArr2.length * 2];
            System.arraycopy(bVarArr2, 0, bVarArr3, bVarArr2.length, bVarArr2.length);
            this.c = ((okhttp3.internal.http2.b[]) this.h).length - 1;
            this.h = bVarArr3;
        }
        int i4 = this.c;
        this.c = i4 - 1;
        ((okhttp3.internal.http2.b[]) this.h)[i4] = bVar;
        this.d++;
        this.e += i2;
    }

    /* JADX WARN: Code restructure failed: missing block: B:47:0x00d7, code lost:
    
        throw new java.lang.IllegalStateException("map/keySet size inconsistency");
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object e(java.lang.Object r6, java.lang.Object r7) {
        /*
            r5 = this;
            r0 = 0
            if (r6 == 0) goto Ldc
            java.lang.Object r1 = r5.f
            com.google.android.gms.internal.mlkit_common.u r1 = (com.google.android.gms.internal.mlkit_common.u) r1
            monitor-enter(r1)
            int r2 = r5.i()     // Catch: java.lang.Throwable -> L23
            int r2 = r2 + 1
            r5.b = r2     // Catch: java.lang.Throwable -> L23
            java.lang.Object r2 = r5.g     // Catch: java.lang.Throwable -> L23
            java.util.HashMap r2 = (java.util.HashMap) r2     // Catch: java.lang.Throwable -> L23
            java.lang.Object r7 = r2.put(r6, r7)     // Catch: java.lang.Throwable -> L23
            if (r7 == 0) goto L26
            int r2 = r5.i()     // Catch: java.lang.Throwable -> L23
            int r2 = r2 + (-1)
            r5.b = r2     // Catch: java.lang.Throwable -> L23
            goto L26
        L23:
            r6 = move-exception
            goto Lda
        L26:
            java.lang.Object r2 = r5.h     // Catch: java.lang.Throwable -> L23
            java.util.LinkedHashSet r2 = (java.util.LinkedHashSet) r2     // Catch: java.lang.Throwable -> L23
            boolean r2 = r2.contains(r6)     // Catch: java.lang.Throwable -> L23
            if (r2 == 0) goto L37
            java.lang.Object r2 = r5.h     // Catch: java.lang.Throwable -> L23
            java.util.LinkedHashSet r2 = (java.util.LinkedHashSet) r2     // Catch: java.lang.Throwable -> L23
            r2.remove(r6)     // Catch: java.lang.Throwable -> L23
        L37:
            java.lang.Object r2 = r5.h     // Catch: java.lang.Throwable -> L23
            java.util.LinkedHashSet r2 = (java.util.LinkedHashSet) r2     // Catch: java.lang.Throwable -> L23
            r2.add(r6)     // Catch: java.lang.Throwable -> L23
            monitor-exit(r1)
            int r6 = r5.c
        L41:
            java.lang.Object r1 = r5.f
            com.google.android.gms.internal.mlkit_common.u r1 = (com.google.android.gms.internal.mlkit_common.u) r1
            monitor-enter(r1)
            int r2 = r5.i()     // Catch: java.lang.Throwable -> L5d
            if (r2 < 0) goto Ld0
            java.lang.Object r2 = r5.g     // Catch: java.lang.Throwable -> L5d
            java.util.HashMap r2 = (java.util.HashMap) r2     // Catch: java.lang.Throwable -> L5d
            boolean r2 = r2.isEmpty()     // Catch: java.lang.Throwable -> L5d
            if (r2 == 0) goto L60
            int r2 = r5.i()     // Catch: java.lang.Throwable -> L5d
            if (r2 != 0) goto Ld0
            goto L60
        L5d:
            r6 = move-exception
            goto Ld8
        L60:
            java.lang.Object r2 = r5.g     // Catch: java.lang.Throwable -> L5d
            java.util.HashMap r2 = (java.util.HashMap) r2     // Catch: java.lang.Throwable -> L5d
            boolean r2 = r2.isEmpty()     // Catch: java.lang.Throwable -> L5d
            java.lang.Object r3 = r5.h     // Catch: java.lang.Throwable -> L5d
            java.util.LinkedHashSet r3 = (java.util.LinkedHashSet) r3     // Catch: java.lang.Throwable -> L5d
            boolean r3 = r3.isEmpty()     // Catch: java.lang.Throwable -> L5d
            if (r2 != r3) goto Ld0
            int r2 = r5.i()     // Catch: java.lang.Throwable -> L5d
            if (r2 <= r6) goto Lbe
            java.lang.Object r2 = r5.g     // Catch: java.lang.Throwable -> L5d
            java.util.HashMap r2 = (java.util.HashMap) r2     // Catch: java.lang.Throwable -> L5d
            boolean r2 = r2.isEmpty()     // Catch: java.lang.Throwable -> L5d
            if (r2 != 0) goto Lbe
            java.lang.Object r2 = r5.h     // Catch: java.lang.Throwable -> L5d
            java.util.LinkedHashSet r2 = (java.util.LinkedHashSet) r2     // Catch: java.lang.Throwable -> L5d
            java.lang.Object r2 = kotlin.collections.CollectionsKt.K(r2)     // Catch: java.lang.Throwable -> L5d
            java.lang.Object r3 = r5.g     // Catch: java.lang.Throwable -> L5d
            java.util.HashMap r3 = (java.util.HashMap) r3     // Catch: java.lang.Throwable -> L5d
            java.lang.Object r3 = r3.get(r2)     // Catch: java.lang.Throwable -> L5d
            if (r3 == 0) goto Lb6
            java.lang.Object r4 = r5.g     // Catch: java.lang.Throwable -> L5d
            java.util.HashMap r4 = (java.util.HashMap) r4     // Catch: java.lang.Throwable -> L5d
            java.util.Map r4 = kotlin.jvm.internal.O.c(r4)     // Catch: java.lang.Throwable -> L5d
            r4.remove(r2)     // Catch: java.lang.Throwable -> L5d
            java.lang.Object r4 = r5.h     // Catch: java.lang.Throwable -> L5d
            java.util.LinkedHashSet r4 = (java.util.LinkedHashSet) r4     // Catch: java.lang.Throwable -> L5d
            java.util.Collection r4 = kotlin.jvm.internal.O.a(r4)     // Catch: java.lang.Throwable -> L5d
            r4.remove(r2)     // Catch: java.lang.Throwable -> L5d
            int r4 = r5.i()     // Catch: java.lang.Throwable -> L5d
            kotlin.jvm.internal.Intrinsics.d(r2)     // Catch: java.lang.Throwable -> L5d
            int r4 = r4 + (-1)
            r5.b = r4     // Catch: java.lang.Throwable -> L5d
            goto Lc0
        Lb6:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException     // Catch: java.lang.Throwable -> L5d
            java.lang.String r7 = "inconsistent state"
            r6.<init>(r7)     // Catch: java.lang.Throwable -> L5d
            throw r6     // Catch: java.lang.Throwable -> L5d
        Lbe:
            r2 = r0
            r3 = r2
        Lc0:
            kotlin.Unit r4 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L5d
            monitor-exit(r1)
            if (r2 != 0) goto Lc8
            if (r3 != 0) goto Lc8
            return r7
        Lc8:
            kotlin.jvm.internal.Intrinsics.d(r2)
            kotlin.jvm.internal.Intrinsics.d(r3)
            goto L41
        Ld0:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException     // Catch: java.lang.Throwable -> L5d
            java.lang.String r7 = "map/keySet size inconsistency"
            r6.<init>(r7)     // Catch: java.lang.Throwable -> L5d
            throw r6     // Catch: java.lang.Throwable -> L5d
        Ld8:
            monitor-exit(r1)
            throw r6
        Lda:
            monitor-exit(r1)
            throw r6
        Ldc:
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.text.caches.b.e(java.lang.Object, java.lang.Object):java.lang.Object");
    }

    public k f() {
        int i;
        A source = (A) this.g;
        byte b = source.readByte();
        byte[] bArr = okhttp3.internal.b.a;
        int i2 = b & 255;
        int i3 = 0;
        boolean z = (b & 128) == 128;
        long jG = g(i2, 127);
        if (!z) {
            return source.d(jG);
        }
        C5091h sink = new C5091h();
        int[] iArr = x.a;
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(sink, "sink");
        U0 u0 = x.c;
        U0 u02 = u0;
        int i4 = 0;
        for (long j = 0; j < jG; j++) {
            byte b2 = source.readByte();
            byte[] bArr2 = okhttp3.internal.b.a;
            i3 = (i3 << 8) | (b2 & 255);
            i4 += 8;
            while (i4 >= 8) {
                U0[] u0Arr = (U0[]) u02.d;
                Intrinsics.d(u0Arr);
                u02 = u0Arr[(i3 >>> (i4 - 8)) & 255];
                Intrinsics.d(u02);
                if (((U0[]) u02.d) == null) {
                    sink.p0(u02.b);
                    i4 -= u02.c;
                    u02 = u0;
                } else {
                    i4 -= 8;
                }
            }
        }
        while (i4 > 0) {
            U0[] u0Arr2 = (U0[]) u02.d;
            Intrinsics.d(u0Arr2);
            U0 u03 = u0Arr2[(i3 << (8 - i4)) & 255];
            Intrinsics.d(u03);
            if (((U0[]) u03.d) != null || (i = u03.c) > i4) {
                break;
            }
            sink.p0(u03.b);
            i4 -= i;
            u02 = u0;
        }
        return sink.D(sink.b);
    }

    public int g(int i, int i2) {
        int i3 = i & i2;
        if (i3 < i2) {
            return i3;
        }
        int i4 = 0;
        while (true) {
            byte b = ((A) this.g).readByte();
            byte[] bArr = okhttp3.internal.b.a;
            int i5 = b & 255;
            if ((b & 128) == 0) {
                return i2 + (i5 << i4);
            }
            i2 += (b & Byte.MAX_VALUE) << i4;
            i4 += 7;
        }
    }

    public Object h(Object obj) {
        Object objRemove;
        synchronized (((u) this.f)) {
            try {
                objRemove = ((HashMap) this.g).remove(obj);
                ((LinkedHashSet) this.h).remove(obj);
                if (objRemove != null) {
                    this.b = i() - 1;
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
        return objRemove;
    }

    public int i() {
        int i;
        synchronized (((u) this.f)) {
            i = this.b;
        }
        return i;
    }

    public String toString() {
        String str;
        switch (this.a) {
            case 0:
                synchronized (((u) this.f)) {
                    try {
                        int i = this.d;
                        int i2 = this.e + i;
                        str = "LruCache[maxSize=" + this.c + ",hits=" + this.d + ",misses=" + this.e + ",hitRate=" + (i2 != 0 ? (i * 100) / i2 : 0) + "%]";
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return str;
            default:
                return super.toString();
        }
    }

    public b(int i) {
        this.a = 0;
        this.f = new u(3);
        if (i > 0) {
            this.c = i;
            this.g = new HashMap(0, 0.75f);
            this.h = new LinkedHashSet();
            return;
        }
        throw new IllegalArgumentException("maxSize <= 0");
    }
}
