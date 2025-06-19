package kotlinx.serialization.internal;

import kotlinx.serialization.KSerializer;

/* loaded from: classes3.dex */
public interface D extends KSerializer {
    KSerializer[] childSerializers();

    default KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
