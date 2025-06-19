package kotlinx.serialization.modules;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;

/* loaded from: classes3.dex */
public final class b extends c {
    public final com.sdk.growthbook.utils.a a;

    public b(com.sdk.growthbook.utils.a provider) {
        Intrinsics.checkNotNullParameter(provider, "provider");
        this.a = provider;
    }

    @Override // kotlinx.serialization.modules.c
    public final KSerializer a(List typeArgumentsSerializers) {
        Intrinsics.checkNotNullParameter(typeArgumentsSerializers, "typeArgumentsSerializers");
        return (KSerializer) this.a.invoke(typeArgumentsSerializers);
    }
}
