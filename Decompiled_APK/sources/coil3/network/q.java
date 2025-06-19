package coil3.network;

import android.os.Looper;
import android.os.NetworkOnMainThreadException;
import com.google.android.gms.internal.mlkit_vision_camera.u3;
import com.google.android.gms.internal.mlkit_vision_camera.w3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3497n;
import java.io.IOException;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.C4937f;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.StringsKt;
import okio.A;
import okio.AbstractC5085b;
import okio.x;

/* loaded from: classes.dex */
public final class q implements coil3.fetch.g {
    public final String a;
    public final coil3.request.m b;
    public final kotlin.u c;
    public final kotlin.u d;
    public final kotlin.u e;
    public final e f;

    public q(String str, coil3.request.m mVar, kotlin.u uVar, kotlin.u uVar2, kotlin.u uVar3, e eVar) {
        this.a = str;
        this.b = mVar;
        this.c = uVar;
        this.d = uVar2;
        this.e = uVar3;
        this.f = eVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(coil3.network.q r4, coil3.network.u r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            boolean r0 = r6 instanceof coil3.network.o
            if (r0 == 0) goto L13
            r0 = r6
            coil3.network.o r0 = (coil3.network.o) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            coil3.network.o r0 = new coil3.network.o
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            okio.h r4 = r0.k
            coil3.network.q r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r6 = r4
            r4 = r5
            goto L4d
        L2d:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            okio.h r6 = new okio.h
            r6.<init>()
            r0.j = r4
            r0.k = r6
            r0.n = r3
            okio.j r5 = r5.a
            r5.e0(r6)
            kotlin.Unit r5 = kotlin.Unit.a
            if (r5 != r1) goto L4d
            return r1
        L4d:
            okio.n r4 = r4.e()
            coil3.decode.s r5 = new coil3.decode.s
            r0 = 0
            r5.<init>(r6, r4, r0)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.network.q.b(coil3.network.q, coil3.network.u, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0218  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x0250  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x0199 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:157:0x024a A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:161:0x0240 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:165:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0020  */
    /* JADX WARN: Type inference failed for: r0v12 */
    /* JADX WARN: Type inference failed for: r0v13, types: [java.lang.Throwable] */
    /* JADX WARN: Type inference failed for: r0v18 */
    /* JADX WARN: Type inference failed for: r0v19, types: [java.lang.Throwable] */
    /* JADX WARN: Type inference failed for: r0v22, types: [java.lang.Throwable] */
    /* JADX WARN: Type inference failed for: r0v23 */
    /* JADX WARN: Type inference failed for: r0v25, types: [java.lang.Throwable] */
    /* JADX WARN: Type inference failed for: r0v26 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object c(coil3.network.q r22, coil3.disk.h r23, coil3.network.t r24, coil3.network.t r25, kotlin.coroutines.jvm.internal.c r26) {
        /*
            Method dump skipped, instructions count: 593
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.network.q.c(coil3.network.q, coil3.disk.h, coil3.network.t, coil3.network.t, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static String f(String str, String str2) {
        String strC;
        if ((str2 == null || D.r(str2, "text/plain", false)) && (strC = AbstractC3497n.c(str)) != null) {
            return strC;
        }
        if (str2 != null) {
            return StringsKt.d0(str2, ';');
        }
        return null;
    }

    /* JADX WARN: Can't wrap try/catch for region: R(9:30|(5:(14:34|(1:36)|37|(1:39)|41|94|42|(2:44|(4:46|(2:51|52)|55|(3:57|(1:60)|78))(2:67|68))|69|66|99|70|(3:73|74|(0)(0))|78)|99|70|(0)|78)|40|41|94|42|(0)|69|66) */
    /* JADX WARN: Code restructure failed: missing block: B:106:?, code lost:
    
        throw r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:107:?, code lost:
    
        throw r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x00ef, code lost:
    
        r0 = e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00f0, code lost:
    
        r1 = r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x019f, code lost:
    
        androidx.compose.ui.node.B.t(r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x01a3, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x01a5, code lost:
    
        throw r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x01a6, code lost:
    
        throw r14;
     */
    /* JADX WARN: Removed duplicated region for block: B:103:0x019f A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:105:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00ad A[Catch: Exception -> 0x00ef, TryCatch #0 {Exception -> 0x00ef, blocks: (B:42:0x00a6, B:44:0x00ad, B:46:0x00bb, B:55:0x00f3, B:57:0x00ff, B:49:0x00d1, B:51:0x00db, B:67:0x0150, B:68:0x0157), top: B:94:0x00a6 }] */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0174  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x017a A[Catch: Exception -> 0x004d, TRY_LEAVE, TryCatch #2 {Exception -> 0x004d, blocks: (B:21:0x0048, B:74:0x0176, B:76:0x017a), top: B:97:0x0048 }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x01a6  */
    @Override // coil3.fetch.g
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.h r14) throws java.lang.Exception {
        /*
            Method dump skipped, instructions count: 423
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.network.q.a(kotlin.coroutines.h):java.lang.Object");
    }

    public final Object d(s sVar, Function2 function2, l lVar) {
        if (this.b.i.a && Intrinsics.b(Looper.myLooper(), Looper.getMainLooper())) {
            throw new NetworkOnMainThreadException();
        }
        coil3.network.okhttp.internal.b bVar = (coil3.network.okhttp.internal.b) this.c.getValue();
        return coil3.network.okhttp.internal.b.a(bVar.a, sVar, new k(function2, null), lVar);
    }

    public final okio.n e() {
        okio.t tVar;
        coil3.disk.i iVar = (coil3.disk.i) this.d.getValue();
        return (iVar == null || (tVar = iVar.a) == null) ? this.b.f : tVar;
    }

    public final s g() {
        androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e eVar = h.b;
        coil3.request.m mVar = this.b;
        r rVar = (r) coil3.n.e(mVar, eVar);
        rVar.getClass();
        com.google.firebase.platforminfo.c cVar = new com.google.firebase.platforminfo.c();
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Map.Entry entry : rVar.a.entrySet()) {
            linkedHashMap.put(entry.getKey(), CollectionsKt.y0((Collection) entry.getValue()));
        }
        cVar.a = linkedHashMap;
        coil3.request.b bVar = mVar.h;
        boolean z = bVar.a;
        boolean z2 = mVar.i.a && this.f.a();
        if (!z2 && z) {
            cVar.o("only-if-cached, max-stale=2147483647");
        } else if (!z2 || z) {
            if (!z2 && !z) {
                cVar.o("no-cache, only-if-cached");
            }
        } else if (bVar.b) {
            cVar.o("no-cache");
        } else {
            cVar.o("no-cache, no-store");
        }
        String str = (String) coil3.n.e(mVar, h.a);
        r rVar2 = new r(V.l((LinkedHashMap) cVar.a));
        if (coil3.n.e(mVar, h.c) == null) {
            return new s(this.a, str, rVar2, mVar.j);
        }
        throw new ClassCastException();
    }

    public final coil3.decode.p h(coil3.disk.h hVar) {
        coil3.disk.b bVar = hVar.a;
        if (bVar.b) {
            throw new IllegalStateException("snapshot is closed");
        }
        x xVar = (x) bVar.a.c.get(1);
        okio.n nVarE = e();
        String str = this.b.e;
        if (str == null) {
            str = this.a;
        }
        return u3.a(xVar, nVarE, str, hVar, 16);
    }

    public final t i(coil3.disk.h hVar) throws Throwable {
        Throwable th;
        t tVarA;
        try {
            okio.n nVarE = e();
            coil3.disk.b bVar = hVar.a;
            if (bVar.b) {
                throw new IllegalStateException("snapshot is closed");
            }
            A aC = AbstractC5085b.c(nVarE.P((x) bVar.a.c.get(0)));
            try {
                tVarA = w3.a(aC);
                try {
                    aC.close();
                    th = null;
                } catch (Throwable th2) {
                    th = th2;
                }
            } catch (Throwable th3) {
                try {
                    aC.close();
                } catch (Throwable th4) {
                    C4937f.a(th3, th4);
                }
                th = th3;
                tVarA = null;
            }
            if (th == null) {
                return tVarA;
            }
            throw th;
        } catch (IOException unused) {
            return null;
        }
    }
}
