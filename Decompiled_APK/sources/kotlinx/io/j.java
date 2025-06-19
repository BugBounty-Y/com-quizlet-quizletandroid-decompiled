package kotlinx.io;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_camera.N1;
import java.io.EOFException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class j {
    public static final char[] a = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public static final void a(long j, long j2, long j3) {
        if (j2 >= 0 && j3 <= j) {
            if (j2 > j3) {
                throw new IllegalArgumentException(d0.q(d0.t(j2, "startIndex (", ") > endIndex ("), j3, ')'));
            }
            return;
        }
        StringBuilder sbT = d0.t(j2, "startIndex (", ") and endIndex (");
        sbT.append(j3);
        sbT.append(") are not within the range [0..size(");
        sbT.append(j);
        sbT.append("))");
        throw new IndexOutOfBoundsException(sbT.toString());
    }

    public static final boolean c(g gVar) {
        Intrinsics.checkNotNullParameter(gVar, "<this>");
        return gVar.b() == 0;
    }

    public static final byte[] d(a aVar, int i) {
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        long j = i;
        if (j >= 0) {
            return e(aVar, i);
        }
        throw new IllegalArgumentException(d0.o(j, "byteCount (", ") < 0").toString());
    }

    public static final byte[] e(i iVar, int i) throws EOFException {
        if (i == -1) {
            for (long j = 2147483647L; iVar.c().c < 2147483647L && iVar.e(j); j *= 2) {
            }
            if (iVar.c().c >= 2147483647L) {
                throw new IllegalStateException(("Can't create an array of size " + iVar.c().c).toString());
            }
            i = (int) iVar.c().c;
        } else {
            iVar.k(i);
        }
        byte[] sink = new byte[i];
        a aVarC = iVar.c();
        Intrinsics.checkNotNullParameter(aVarC, "<this>");
        Intrinsics.checkNotNullParameter(sink, "sink");
        long j2 = i;
        int i2 = 0;
        a(j2, 0, j2);
        while (i2 < i) {
            int iG0 = aVarC.g0(i2, sink, i);
            if (iG0 == -1) {
                throw new EOFException(android.support.v4.media.session.a.j("Source exhausted before reading ", i, " bytes. Only ", " bytes were read.", iG0));
            }
            i2 += iG0;
        }
        return sink;
    }

    public static final String f(i iVar) throws EOFException {
        Intrinsics.checkNotNullParameter(iVar, "<this>");
        iVar.e(Long.MAX_VALUE);
        a aVarC = iVar.c();
        long j = iVar.c().c;
        if (j == 0) {
            return "";
        }
        g gVar = aVarC.a;
        if (gVar == null) {
            throw new IllegalStateException("Unreacheable");
        }
        if (gVar.b() < j) {
            byte[] bArrD = d(aVarC, (int) j);
            return N1.f(0, bArrD, bArrD.length);
        }
        int i = gVar.b;
        String strF = N1.f(i, gVar.a, Math.min(gVar.c, ((int) j) + i));
        aVarC.skip(j);
        return strF;
    }

    public abstract boolean b();

    public abstract boolean g();
}
