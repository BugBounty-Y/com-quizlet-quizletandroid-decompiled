package kotlinx.serialization.internal;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* renamed from: kotlinx.serialization.internal.x, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5069x {
    public static final long[] e = new long[0];
    public final SerialDescriptor a;
    public final com.quizlet.search.composables.M b;
    public long c;
    public final long[] d;

    public C5069x(SerialDescriptor descriptor, com.quizlet.search.composables.M readIfAbsent) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(readIfAbsent, "readIfAbsent");
        this.a = descriptor;
        this.b = readIfAbsent;
        int iF = descriptor.f();
        if (iF <= 64) {
            this.c = iF != 64 ? (-1) << iF : 0L;
            this.d = e;
            return;
        }
        this.c = 0L;
        int i = (iF - 1) >>> 6;
        long[] jArr = new long[i];
        if ((iF & 63) != 0) {
            Intrinsics.checkNotNullParameter(jArr, "<this>");
            jArr[i - 1] = (-1) << iF;
        }
        this.d = jArr;
    }
}
