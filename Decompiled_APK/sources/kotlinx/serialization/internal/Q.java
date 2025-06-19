package kotlinx.serialization.internal;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;

/* loaded from: classes3.dex */
public final /* synthetic */ class Q implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ KSerializer b;
    public final /* synthetic */ KSerializer c;

    public /* synthetic */ Q(KSerializer kSerializer, KSerializer kSerializer2, int i) {
        this.a = i;
        this.b = kSerializer;
        this.c = kSerializer2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        kotlinx.serialization.descriptors.a buildSerialDescriptor = (kotlinx.serialization.descriptors.a) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(buildSerialDescriptor, "$this$buildSerialDescriptor");
                kotlinx.serialization.descriptors.a.a(buildSerialDescriptor, "key", this.b.getDescriptor());
                kotlinx.serialization.descriptors.a.a(buildSerialDescriptor, "value", this.c.getDescriptor());
                break;
            default:
                Intrinsics.checkNotNullParameter(buildSerialDescriptor, "$this$buildClassSerialDescriptor");
                kotlinx.serialization.descriptors.a.a(buildSerialDescriptor, "first", this.b.getDescriptor());
                kotlinx.serialization.descriptors.a.a(buildSerialDescriptor, "second", this.c.getDescriptor());
                break;
        }
        return Unit.a;
    }
}
