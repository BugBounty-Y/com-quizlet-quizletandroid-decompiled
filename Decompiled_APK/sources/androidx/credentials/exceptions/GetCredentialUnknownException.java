package androidx.credentials.exceptions;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class GetCredentialUnknownException extends GetCredentialException {
    public GetCredentialUnknownException() {
        this(null);
    }

    public GetCredentialUnknownException(CharSequence charSequence) {
        super(charSequence, "android.credentials.GetCredentialException.TYPE_UNKNOWN");
    }
}
