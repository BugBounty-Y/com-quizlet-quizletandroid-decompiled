package kotlinx.serialization;

import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class UnknownFieldException extends SerializationException {
    public UnknownFieldException(int i) {
        super(android.support.v4.media.session.a.f(i, "An unknown field for index "));
    }
}
