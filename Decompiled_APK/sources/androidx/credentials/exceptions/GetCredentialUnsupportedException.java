package androidx.credentials.exceptions;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class GetCredentialUnsupportedException extends GetCredentialException {
    public GetCredentialUnsupportedException() {
        this(null);
    }

    public GetCredentialUnsupportedException(CharSequence charSequence) {
        super(charSequence, "androidx.credentials.TYPE_GET_CREDENTIAL_UNSUPPORTED_EXCEPTION");
    }
}
