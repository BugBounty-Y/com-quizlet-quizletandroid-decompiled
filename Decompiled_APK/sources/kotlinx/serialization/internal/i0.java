package kotlinx.serialization.internal;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.jvm.internal.C4943b;
import kotlin.jvm.internal.C4944c;
import kotlin.jvm.internal.C4947f;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.C4951j;
import kotlin.jvm.internal.C4952k;
import kotlin.jvm.internal.C4957p;
import kotlin.jvm.internal.C4959s;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;

/* loaded from: classes3.dex */
public abstract class i0 {
    public static final kotlin.collections.builders.h a;

    static {
        kotlin.collections.builders.h builder = new kotlin.collections.builders.h();
        C4950i c4950iA = kotlin.jvm.internal.K.a(String.class);
        R1.g(kotlin.jvm.internal.N.a);
        builder.put(c4950iA, q0.a);
        C4950i c4950iA2 = kotlin.jvm.internal.K.a(Character.TYPE);
        Intrinsics.checkNotNullParameter(C4947f.a, "<this>");
        builder.put(c4950iA2, C5062p.a);
        builder.put(kotlin.jvm.internal.K.a(char[].class), C5061o.c);
        C4950i c4950iA3 = kotlin.jvm.internal.K.a(Double.TYPE);
        Intrinsics.checkNotNullParameter(C4951j.a, "<this>");
        builder.put(c4950iA3, C5067v.a);
        builder.put(kotlin.jvm.internal.K.a(double[].class), C5066u.c);
        C4950i c4950iA4 = kotlin.jvm.internal.K.a(Float.TYPE);
        R1.f(C4952k.a);
        builder.put(c4950iA4, C.a);
        builder.put(kotlin.jvm.internal.K.a(float[].class), B.c);
        C4950i c4950iA5 = kotlin.jvm.internal.K.a(Long.TYPE);
        Intrinsics.checkNotNullParameter(C4959s.a, "<this>");
        builder.put(c4950iA5, P.a);
        builder.put(kotlin.jvm.internal.K.a(long[].class), O.c);
        C4950i c4950iA6 = kotlin.jvm.internal.K.a(kotlin.D.class);
        Intrinsics.checkNotNullParameter(kotlin.D.b, "<this>");
        builder.put(c4950iA6, z0.a);
        C4950i c4950iA7 = kotlin.jvm.internal.K.a(Integer.TYPE);
        Intrinsics.checkNotNullParameter(C4957p.a, "<this>");
        builder.put(c4950iA7, K.a);
        builder.put(kotlin.jvm.internal.K.a(int[].class), J.c);
        C4950i c4950iA8 = kotlin.jvm.internal.K.a(kotlin.A.class);
        Intrinsics.checkNotNullParameter(kotlin.A.b, "<this>");
        builder.put(c4950iA8, w0.a);
        C4950i c4950iA9 = kotlin.jvm.internal.K.a(Short.TYPE);
        Intrinsics.checkNotNullParameter(kotlin.jvm.internal.M.a, "<this>");
        builder.put(c4950iA9, p0.a);
        builder.put(kotlin.jvm.internal.K.a(short[].class), o0.c);
        C4950i c4950iA10 = kotlin.jvm.internal.K.a(kotlin.H.class);
        Intrinsics.checkNotNullParameter(kotlin.H.b, "<this>");
        builder.put(c4950iA10, C0.a);
        C4950i c4950iA11 = kotlin.jvm.internal.K.a(Byte.TYPE);
        Intrinsics.checkNotNullParameter(C4944c.a, "<this>");
        builder.put(c4950iA11, C5056j.a);
        builder.put(kotlin.jvm.internal.K.a(byte[].class), C5055i.c);
        C4950i c4950iA12 = kotlin.jvm.internal.K.a(kotlin.x.class);
        Intrinsics.checkNotNullParameter(kotlin.x.b, "<this>");
        builder.put(c4950iA12, t0.a);
        C4950i c4950iA13 = kotlin.jvm.internal.K.a(Boolean.TYPE);
        Intrinsics.checkNotNullParameter(C4943b.a, "<this>");
        builder.put(c4950iA13, C5053g.a);
        builder.put(kotlin.jvm.internal.K.a(boolean[].class), C5052f.c);
        C4950i c4950iA14 = kotlin.jvm.internal.K.a(Unit.class);
        Intrinsics.checkNotNullParameter(Unit.a, "<this>");
        builder.put(c4950iA14, D0.b);
        builder.put(kotlin.jvm.internal.K.a(Void.class), X.a);
        try {
            C4950i c4950iA15 = kotlin.jvm.internal.K.a(kotlin.time.b.class);
            Intrinsics.checkNotNullParameter(kotlin.time.b.b, "<this>");
            builder.put(c4950iA15, C5068w.a);
        } catch (ClassNotFoundException | NoClassDefFoundError unused) {
        }
        try {
            builder.put(kotlin.jvm.internal.K.a(kotlin.E.class), y0.c);
        } catch (ClassNotFoundException | NoClassDefFoundError unused2) {
        }
        try {
            builder.put(kotlin.jvm.internal.K.a(kotlin.B.class), v0.c);
        } catch (ClassNotFoundException | NoClassDefFoundError unused3) {
        }
        try {
            builder.put(kotlin.jvm.internal.K.a(kotlin.I.class), B0.c);
        } catch (ClassNotFoundException | NoClassDefFoundError unused4) {
        }
        try {
            builder.put(kotlin.jvm.internal.K.a(kotlin.y.class), s0.c);
        } catch (ClassNotFoundException | NoClassDefFoundError unused5) {
        }
        try {
            C4950i c4950iA16 = kotlin.jvm.internal.K.a(kotlin.uuid.a.class);
            Intrinsics.checkNotNullParameter(kotlin.uuid.a.c, "<this>");
            builder.put(c4950iA16, E0.a);
        } catch (ClassNotFoundException | NoClassDefFoundError unused6) {
        }
        Intrinsics.checkNotNullParameter(builder, "builder");
        a = builder.b();
    }

    public static final void a(String serialName) {
        Intrinsics.checkNotNullParameter(serialName, "serialName");
        Iterator it2 = ((androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.j) a.values()).iterator();
        while (it2.hasNext()) {
            KSerializer kSerializer = (KSerializer) it2.next();
            if (serialName.equals(kSerializer.getDescriptor().a())) {
                StringBuilder sbY = android.support.v4.media.session.a.y("\n                The name of serial descriptor should uniquely identify associated serializer.\n                For serial name ", serialName, " there already exists ");
                sbY.append(kotlin.jvm.internal.K.a(kSerializer.getClass()).f());
                sbY.append(".\n                Please refer to SerialDescriptor documentation for additional information.\n            ");
                throw new IllegalArgumentException(kotlin.text.x.c(sbY.toString()));
            }
        }
    }
}
