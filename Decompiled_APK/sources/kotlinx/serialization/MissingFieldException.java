package kotlinx.serialization;

import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class MissingFieldException extends SerializationException {
    public final ArrayList a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MissingFieldException(ArrayList missingFields, String str, MissingFieldException missingFieldException) {
        super(str, missingFieldException);
        Intrinsics.checkNotNullParameter(missingFields, "missingFields");
        this.a = missingFields;
    }
}
