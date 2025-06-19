package com.quizlet.local.datastore.models.metering;

import androidx.datastore.core.CorruptionException;
import androidx.datastore.core.f0;
import com.quizlet.data.model.C4179x0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.data.model.o2;
import com.quizlet.generated.enums.O;
import com.quizlet.generated.enums.P;
import com.quizlet.generated.enums.Q;
import com.quizlet.generated.enums.S;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j implements f0 {
    public static final j a = new j();

    public static InterfaceC4176w0 d(d local) {
        Intrinsics.checkNotNullParameter(local, "local");
        if (local.E() == -1 && local.H() == -1) {
            O o = P.Companion;
            int iD = local.D();
            o.getClass();
            P pA = O.a(iD);
            Long lValueOf = Long.valueOf(local.G());
            long jI = local.I();
            Q q = S.Companion;
            int iF = local.F();
            q.getClass();
            return new o2(pA, lValueOf, jI, Q.a(iF));
        }
        int iE = local.E();
        int iH = local.H();
        O o2 = P.Companion;
        int iD2 = local.D();
        o2.getClass();
        P pA2 = O.a(iD2);
        Long lValueOf2 = Long.valueOf(local.G());
        long jI2 = local.I();
        Q q2 = S.Companion;
        int iF2 = local.F();
        q2.getClass();
        return new C4179x0(iE, iH, pA2, lValueOf2, jI2, Q.a(iF2));
    }

    @Override // androidx.datastore.core.f0
    public Object a() {
        n nVarY = n.y();
        Intrinsics.checkNotNullExpressionValue(nVarY, "getDefaultInstance(...)");
        return nVarY;
    }

    @Override // androidx.datastore.core.f0
    public Object b(InputStream inputStream) throws CorruptionException {
        try {
            n nVarZ = n.z(inputStream);
            Intrinsics.checkNotNullExpressionValue(nVarZ, "parseFrom(...)");
            return nVarZ;
        } catch (IOException e) {
            Intrinsics.checkNotNullParameter("Cannot read metering proto.", "message");
            throw new CorruptionException("Cannot read metering proto.", e);
        }
    }

    @Override // androidx.datastore.core.f0
    public Unit c(Object obj, OutputStream outputStream) {
        ((n) obj).j(outputStream);
        return Unit.a;
    }
}
