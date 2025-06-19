package androidx.datastore.preferences.core;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.material.V;
import androidx.datastore.core.C1072d;
import androidx.datastore.core.CorruptionException;
import androidx.datastore.core.InterfaceC1070b;
import androidx.datastore.core.P;
import androidx.datastore.core.U;
import androidx.datastore.core.f0;
import androidx.datastore.preferences.protobuf.AbstractC1113u;
import androidx.datastore.preferences.protobuf.AbstractC1115w;
import androidx.datastore.preferences.protobuf.C1100g;
import androidx.datastore.preferences.protobuf.C1104k;
import androidx.datastore.preferences.protobuf.InterfaceC1114v;
import androidx.datastore.preferences.protobuf.InvalidProtocolBufferException;
import com.google.android.gms.internal.mlkit_vision_barcode.Q6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;

/* loaded from: classes.dex */
public final class e implements f0 {
    public static final e a = new e();

    public static d d(com.airbnb.lottie.network.c cVar, List migrations, C scope, Function0 produceFile) {
        Intrinsics.checkNotNullParameter(migrations, "migrations");
        Intrinsics.checkNotNullParameter(scope, "scope");
        Intrinsics.checkNotNullParameter(produceFile, "produceFile");
        U storage = new U(a, new V(5, produceFile));
        Intrinsics.checkNotNullParameter(storage, "storage");
        Intrinsics.checkNotNullParameter(migrations, "migrations");
        Intrinsics.checkNotNullParameter(scope, "scope");
        Intrinsics.checkNotNullParameter(storage, "storage");
        Intrinsics.checkNotNullParameter(migrations, "migrations");
        Intrinsics.checkNotNullParameter(scope, "scope");
        InterfaceC1070b aVar = cVar;
        if (cVar == null) {
            aVar = new com.quizlet.shared.usecase.folderstudymaterials.a(3);
        }
        Intrinsics.checkNotNullParameter(migrations, "migrations");
        return new d(new d(new P(storage, A.b(new C1072d(migrations, null)), aVar, scope)));
    }

    public static d e(com.airbnb.lottie.network.c cVar, Function0 function0, int i) {
        if ((i & 1) != 0) {
            cVar = null;
        }
        K k = K.a;
        kotlinx.coroutines.scheduling.e eVar = O.a;
        return d(cVar, k, E.c(kotlinx.coroutines.scheduling.d.b.plus(E.e())), function0);
    }

    @Override // androidx.datastore.core.f0
    public Object a() {
        return Q6.a();
    }

    @Override // androidx.datastore.core.f0
    public Object b(InputStream input) throws CorruptionException {
        byte[] bArr;
        Intrinsics.checkNotNullParameter(input, "input");
        try {
            androidx.datastore.preferences.d dVarO = androidx.datastore.preferences.d.o(input);
            Intrinsics.checkNotNullExpressionValue(dVarO, "{\n                Prefer…From(input)\n            }");
            g[] pairs = new g[0];
            Intrinsics.checkNotNullParameter(pairs, "pairs");
            b bVar = new b(false);
            g[] pairs2 = (g[]) Arrays.copyOf(pairs, 0);
            Intrinsics.checkNotNullParameter(pairs2, "pairs");
            bVar.b();
            if (pairs2.length > 0) {
                g gVar = pairs2[0];
                throw null;
            }
            Map mapM = dVarO.m();
            Intrinsics.checkNotNullExpressionValue(mapM, "preferencesProto.preferencesMap");
            for (Map.Entry entry : mapM.entrySet()) {
                String name = (String) entry.getKey();
                androidx.datastore.preferences.h value = (androidx.datastore.preferences.h) entry.getValue();
                Intrinsics.checkNotNullExpressionValue(name, "name");
                Intrinsics.checkNotNullExpressionValue(value, "value");
                int iC = value.C();
                switch (iC == 0 ? -1 : h.a[AbstractC0147y.k(iC)]) {
                    case -1:
                        throw new CorruptionException("Value case is null.", 0);
                    case 0:
                    default:
                        throw new NoWhenBranchMatchedException();
                    case 1:
                        f key = R6.a(name);
                        Boolean boolValueOf = Boolean.valueOf(value.t());
                        Intrinsics.checkNotNullParameter(key, "key");
                        bVar.f(key, boolValueOf);
                        break;
                    case 2:
                        Intrinsics.checkNotNullParameter(name, "name");
                        f key2 = new f(name);
                        Float fValueOf = Float.valueOf(value.x());
                        Intrinsics.checkNotNullParameter(key2, "key");
                        bVar.f(key2, fValueOf);
                        break;
                    case 3:
                        Intrinsics.checkNotNullParameter(name, "name");
                        f key3 = new f(name);
                        Double dValueOf = Double.valueOf(value.w());
                        Intrinsics.checkNotNullParameter(key3, "key");
                        bVar.f(key3, dValueOf);
                        break;
                    case 4:
                        f key4 = R6.c(name);
                        Integer numValueOf = Integer.valueOf(value.y());
                        Intrinsics.checkNotNullParameter(key4, "key");
                        bVar.f(key4, numValueOf);
                        break;
                    case 5:
                        Intrinsics.checkNotNullParameter(name, "name");
                        f key5 = new f(name);
                        Long lValueOf = Long.valueOf(value.z());
                        Intrinsics.checkNotNullParameter(key5, "key");
                        bVar.f(key5, lValueOf);
                        break;
                    case 6:
                        f key6 = R6.d(name);
                        String strA = value.A();
                        Intrinsics.checkNotNullExpressionValue(strA, "value.string");
                        Intrinsics.checkNotNullParameter(key6, "key");
                        bVar.f(key6, strA);
                        break;
                    case 7:
                        Intrinsics.checkNotNullParameter(name, "name");
                        f key7 = new f(name);
                        InterfaceC1114v interfaceC1114vN = value.B().n();
                        Intrinsics.checkNotNullExpressionValue(interfaceC1114vN, "value.stringSet.stringsList");
                        Set setA0 = CollectionsKt.A0(interfaceC1114vN);
                        Intrinsics.checkNotNullParameter(key7, "key");
                        bVar.f(key7, setA0);
                        break;
                    case 8:
                        Intrinsics.checkNotNullParameter(name, "name");
                        f key8 = new f(name);
                        C1100g c1100gU = value.u();
                        int size = c1100gU.size();
                        if (size == 0) {
                            bArr = AbstractC1115w.b;
                        } else {
                            byte[] bArr2 = new byte[size];
                            c1100gU.e(size, bArr2);
                            bArr = bArr2;
                        }
                        Intrinsics.checkNotNullExpressionValue(bArr, "value.bytes.toByteArray()");
                        Intrinsics.checkNotNullParameter(key8, "key");
                        bVar.f(key8, bArr);
                        break;
                    case 9:
                        throw new CorruptionException("Value not set.", 0);
                }
            }
            return bVar.h();
        } catch (InvalidProtocolBufferException e) {
            Intrinsics.checkNotNullParameter("Unable to parse preferences proto.", "message");
            throw new CorruptionException("Unable to parse preferences proto.", e);
        }
    }

    @Override // androidx.datastore.core.f0
    public Unit c(Object obj, OutputStream outputStream) throws IOException {
        AbstractC1113u abstractC1113uB;
        Map mapA = ((b) obj).a();
        androidx.datastore.preferences.b bVarN = androidx.datastore.preferences.d.n();
        for (Map.Entry entry : mapA.entrySet()) {
            f fVar = (f) entry.getKey();
            Object value = entry.getValue();
            String str = fVar.a;
            if (value instanceof Boolean) {
                androidx.datastore.preferences.g gVarD = androidx.datastore.preferences.h.D();
                boolean zBooleanValue = ((Boolean) value).booleanValue();
                gVarD.d();
                androidx.datastore.preferences.h.q((androidx.datastore.preferences.h) gVarD.b, zBooleanValue);
                abstractC1113uB = gVarD.b();
                Intrinsics.checkNotNullExpressionValue(abstractC1113uB, "newBuilder().setBoolean(value).build()");
            } else if (value instanceof Float) {
                androidx.datastore.preferences.g gVarD2 = androidx.datastore.preferences.h.D();
                float fFloatValue = ((Number) value).floatValue();
                gVarD2.d();
                androidx.datastore.preferences.h.r((androidx.datastore.preferences.h) gVarD2.b, fFloatValue);
                abstractC1113uB = gVarD2.b();
                Intrinsics.checkNotNullExpressionValue(abstractC1113uB, "newBuilder().setFloat(value).build()");
            } else if (value instanceof Double) {
                androidx.datastore.preferences.g gVarD3 = androidx.datastore.preferences.h.D();
                double dDoubleValue = ((Number) value).doubleValue();
                gVarD3.d();
                androidx.datastore.preferences.h.o((androidx.datastore.preferences.h) gVarD3.b, dDoubleValue);
                abstractC1113uB = gVarD3.b();
                Intrinsics.checkNotNullExpressionValue(abstractC1113uB, "newBuilder().setDouble(value).build()");
            } else if (value instanceof Integer) {
                androidx.datastore.preferences.g gVarD4 = androidx.datastore.preferences.h.D();
                int iIntValue = ((Number) value).intValue();
                gVarD4.d();
                androidx.datastore.preferences.h.s((androidx.datastore.preferences.h) gVarD4.b, iIntValue);
                abstractC1113uB = gVarD4.b();
                Intrinsics.checkNotNullExpressionValue(abstractC1113uB, "newBuilder().setInteger(value).build()");
            } else if (value instanceof Long) {
                androidx.datastore.preferences.g gVarD5 = androidx.datastore.preferences.h.D();
                long jLongValue = ((Number) value).longValue();
                gVarD5.d();
                androidx.datastore.preferences.h.l((androidx.datastore.preferences.h) gVarD5.b, jLongValue);
                abstractC1113uB = gVarD5.b();
                Intrinsics.checkNotNullExpressionValue(abstractC1113uB, "newBuilder().setLong(value).build()");
            } else if (value instanceof String) {
                androidx.datastore.preferences.g gVarD6 = androidx.datastore.preferences.h.D();
                gVarD6.d();
                androidx.datastore.preferences.h.m((androidx.datastore.preferences.h) gVarD6.b, (String) value);
                abstractC1113uB = gVarD6.b();
                Intrinsics.checkNotNullExpressionValue(abstractC1113uB, "newBuilder().setString(value).build()");
            } else if (value instanceof Set) {
                androidx.datastore.preferences.g gVarD7 = androidx.datastore.preferences.h.D();
                androidx.datastore.preferences.e eVarO = androidx.datastore.preferences.f.o();
                Intrinsics.e(value, "null cannot be cast to non-null type kotlin.collections.Set<kotlin.String>");
                eVarO.d();
                androidx.datastore.preferences.f.l((androidx.datastore.preferences.f) eVarO.b, (Set) value);
                gVarD7.d();
                androidx.datastore.preferences.h.n((androidx.datastore.preferences.h) gVarD7.b, (androidx.datastore.preferences.f) eVarO.b());
                abstractC1113uB = gVarD7.b();
                Intrinsics.checkNotNullExpressionValue(abstractC1113uB, "newBuilder()\n           …                 .build()");
            } else {
                if (!(value instanceof byte[])) {
                    throw new IllegalStateException("PreferencesSerializer does not support type: ".concat(value.getClass().getName()));
                }
                androidx.datastore.preferences.g gVarD8 = androidx.datastore.preferences.h.D();
                byte[] bArr = (byte[]) value;
                C1100g c1100g = C1100g.c;
                C1100g c1100gC = C1100g.c(0, bArr, bArr.length);
                gVarD8.d();
                androidx.datastore.preferences.h.p((androidx.datastore.preferences.h) gVarD8.b, c1100gC);
                abstractC1113uB = gVarD8.b();
                Intrinsics.checkNotNullExpressionValue(abstractC1113uB, "newBuilder().setBytes(By….copyFrom(value)).build()");
            }
            bVarN.getClass();
            str.getClass();
            bVarN.d();
            androidx.datastore.preferences.d.l((androidx.datastore.preferences.d) bVarN.b).put(str, (androidx.datastore.preferences.h) abstractC1113uB);
        }
        androidx.datastore.preferences.d dVar = (androidx.datastore.preferences.d) bVarN.b();
        int iA = dVar.a(null);
        Logger logger = C1104k.g;
        if (iA > 4096) {
            iA = 4096;
        }
        C1104k c1104k = new C1104k(outputStream, iA);
        dVar.b(c1104k);
        if (c1104k.e > 0) {
            c1104k.m();
        }
        return Unit.a;
    }
}
