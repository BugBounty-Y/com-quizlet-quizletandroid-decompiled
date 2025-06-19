package androidx.glance.appwidget.proto;

import androidx.datastore.core.CorruptionException;
import androidx.datastore.core.f0;
import androidx.glance.appwidget.protobuf.A;
import androidx.glance.appwidget.protobuf.C1198j;
import androidx.glance.appwidget.protobuf.InvalidProtocolBufferException;
import androidx.glance.appwidget.protobuf.L;
import androidx.glance.appwidget.protobuf.O;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Logger;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class l implements f0 {
    public static final l a = new l();
    public static final e b;

    static {
        e eVarN = e.n();
        Intrinsics.checkNotNullExpressionValue(eVarN, "getDefaultInstance()");
        b = eVarN;
    }

    @Override // androidx.datastore.core.f0
    public final Object a() {
        return b;
    }

    @Override // androidx.datastore.core.f0
    public final Object b(InputStream inputStream) throws CorruptionException {
        try {
            e eVarQ = e.q(inputStream);
            Intrinsics.checkNotNullExpressionValue(eVarQ, "parseFrom(input)");
            return eVarQ;
        } catch (InvalidProtocolBufferException e) {
            Intrinsics.checkNotNullParameter("Cannot read proto.", "message");
            throw new CorruptionException("Cannot read proto.", e);
        }
    }

    @Override // androidx.datastore.core.f0
    public final Unit c(Object obj, OutputStream outputStream) throws IOException {
        e eVar = (e) obj;
        eVar.getClass();
        int iA = eVar.a(null);
        Logger logger = C1198j.g;
        if (iA > 4096) {
            iA = 4096;
        }
        C1198j c1198j = new C1198j(outputStream, iA);
        eVar.getClass();
        L l = L.c;
        l.getClass();
        O oA = l.a(eVar.getClass());
        A a2 = c1198j.b;
        if (a2 == null) {
            a2 = new A(c1198j);
        }
        oA.h(eVar, a2);
        if (c1198j.e > 0) {
            c1198j.m();
        }
        return Unit.a;
    }
}
