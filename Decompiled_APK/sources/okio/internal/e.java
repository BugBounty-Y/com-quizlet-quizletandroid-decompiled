package okio.internal;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.io.EOFException;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;
import okio.k;
import okio.x;

/* loaded from: classes3.dex */
public abstract class e {
    public static final k a;
    public static final k b;
    public static final k c;
    public static final k d;
    public static final k e;

    static {
        k kVar = k.d;
        a = com.quizlet.quizletandroid.ui.common.images.capture.b.i("/");
        b = com.quizlet.quizletandroid.ui.common.images.capture.b.i("\\");
        c = com.quizlet.quizletandroid.ui.common.images.capture.b.i("/\\");
        d = com.quizlet.quizletandroid.ui.common.images.capture.b.i(".");
        e = com.quizlet.quizletandroid.ui.common.images.capture.b.i("..");
    }

    public static final int a(x xVar) {
        if (xVar.a.d() != 0) {
            k kVar = xVar.a;
            if (kVar.j(0) != 47) {
                if (kVar.j(0) == 92) {
                    if (kVar.d() > 2 && kVar.j(1) == 92) {
                        k other = b;
                        Intrinsics.checkNotNullParameter(other, "other");
                        int iF = kVar.f(2, other.a);
                        return iF == -1 ? kVar.d() : iF;
                    }
                } else if (kVar.d() > 2 && kVar.j(1) == 58 && kVar.j(2) == 92) {
                    char cJ = (char) kVar.j(0);
                    if ('a' <= cJ && cJ < '{') {
                        return 3;
                    }
                    if ('A' <= cJ && cJ < '[') {
                        return 3;
                    }
                }
            }
            return 1;
        }
        return -1;
    }

    public static final x b(x xVar, x child, boolean z) {
        Intrinsics.checkNotNullParameter(xVar, "<this>");
        Intrinsics.checkNotNullParameter(child, "child");
        child.getClass();
        if (a(child) != -1 || child.i() != null) {
            return child;
        }
        k kVarC = c(xVar);
        if (kVarC == null && (kVarC = c(child)) == null) {
            kVarC = f(x.b);
        }
        C5091h c5091h = new C5091h();
        c5091h.m0(xVar.a);
        if (c5091h.b > 0) {
            c5091h.m0(kVarC);
        }
        c5091h.m0(child.a);
        return d(c5091h, z);
    }

    public static final k c(x xVar) {
        k kVar = xVar.a;
        k kVar2 = a;
        if (k.g(kVar, kVar2) != -1) {
            return kVar2;
        }
        k kVar3 = b;
        if (k.g(xVar.a, kVar3) != -1) {
            return kVar3;
        }
        return null;
    }

    public static final x d(C5091h c5091h, boolean z) throws EOFException {
        long j;
        k kVar;
        k kVar2;
        char cP;
        k kVar3;
        k kVarD;
        Intrinsics.checkNotNullParameter(c5091h, "<this>");
        C5091h c5091h2 = new C5091h();
        k kVarE = null;
        int i = 0;
        while (true) {
            j = 0;
            if (!c5091h.J(0L, a)) {
                kVar = b;
                if (!c5091h.J(0L, kVar)) {
                    break;
                }
            }
            byte b2 = c5091h.readByte();
            if (kVarE == null) {
                kVarE = e(b2);
            }
            i++;
        }
        boolean z2 = i >= 2 && Intrinsics.b(kVarE, kVar);
        k kVar4 = c;
        if (z2) {
            Intrinsics.d(kVarE);
            c5091h2.m0(kVarE);
            c5091h2.m0(kVarE);
        } else if (i > 0) {
            Intrinsics.d(kVarE);
            c5091h2.m0(kVarE);
        } else {
            long jX = c5091h.x(kVar4);
            if (kVarE == null) {
                kVarE = jX == -1 ? f(x.b) : e(c5091h.p(jX));
            }
            if (Intrinsics.b(kVarE, kVar)) {
                kVar2 = kVarE;
                if (c5091h.b >= 2 && c5091h.p(1L) == 58 && (('a' <= (cP = (char) c5091h.p(0L)) && cP < '{') || ('A' <= cP && cP < '['))) {
                    if (jX == 2) {
                        c5091h2.L(c5091h, 3L);
                    } else {
                        c5091h2.L(c5091h, 2L);
                    }
                }
            } else {
                kVar2 = kVarE;
            }
            Unit unit = Unit.a;
            kVarE = kVar2;
        }
        boolean z3 = c5091h2.b > 0;
        ArrayList arrayList = new ArrayList();
        while (true) {
            boolean zU = c5091h.u();
            kVar3 = d;
            if (zU) {
                break;
            }
            long j2 = j;
            long jX2 = c5091h.x(kVar4);
            if (jX2 == -1) {
                kVarD = c5091h.D(c5091h.b);
            } else {
                kVarD = c5091h.D(jX2);
                c5091h.readByte();
            }
            k kVar5 = e;
            if (Intrinsics.b(kVarD, kVar5)) {
                if (!z3 || !arrayList.isEmpty()) {
                    if (!z || (!z3 && (arrayList.isEmpty() || Intrinsics.b(CollectionsKt.U(arrayList), kVar5)))) {
                        arrayList.add(kVarD);
                    } else if (!z2 || arrayList.size() != 1) {
                        Intrinsics.checkNotNullParameter(arrayList, "<this>");
                        if (!arrayList.isEmpty()) {
                            arrayList.remove(B.i(arrayList));
                        }
                    }
                }
            } else if (!Intrinsics.b(kVarD, kVar3) && !Intrinsics.b(kVarD, k.d)) {
                arrayList.add(kVarD);
            }
            j = j2;
        }
        long j3 = j;
        int size = arrayList.size();
        for (int i2 = 0; i2 < size; i2++) {
            if (i2 > 0) {
                c5091h2.m0(kVarE);
            }
            c5091h2.m0((k) arrayList.get(i2));
        }
        if (c5091h2.b == j3) {
            c5091h2.m0(kVar3);
        }
        return new x(c5091h2.D(c5091h2.b));
    }

    public static final k e(byte b2) {
        if (b2 == 47) {
            return a;
        }
        if (b2 == 92) {
            return b;
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(b2, "not a directory separator: "));
    }

    public static final k f(String str) {
        if (Intrinsics.b(str, "/")) {
            return a;
        }
        if (Intrinsics.b(str, "\\")) {
            return b;
        }
        throw new IllegalArgumentException(AbstractC0147y.d("not a directory separator: ", str));
    }
}
