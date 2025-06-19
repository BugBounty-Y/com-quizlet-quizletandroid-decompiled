package kotlinx.coroutines.channels;

import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class i extends C4956o implements Function2 {
    public static final i a = new i(2, j.class, "createSegment", "createSegment(JLkotlinx/coroutines/channels/ChannelSegment;)Lkotlinx/coroutines/channels/ChannelSegment;", 1);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        long jLongValue = ((Number) obj).longValue();
        p pVar = (p) obj2;
        p pVar2 = j.a;
        h hVar = pVar.e;
        Intrinsics.d(hVar);
        return new p(jLongValue, pVar, hVar, 0);
    }
}
