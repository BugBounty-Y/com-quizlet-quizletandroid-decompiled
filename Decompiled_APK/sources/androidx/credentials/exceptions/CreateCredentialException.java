package androidx.credentials.exceptions;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public abstract class CreateCredentialException extends Exception {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CreateCredentialException(CharSequence charSequence, String type) {
        super(charSequence != null ? charSequence.toString() : null);
        Intrinsics.checkNotNullParameter(type, "type");
    }
}
