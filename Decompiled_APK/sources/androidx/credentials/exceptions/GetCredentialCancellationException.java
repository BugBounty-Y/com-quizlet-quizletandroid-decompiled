package androidx.credentials.exceptions;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class GetCredentialCancellationException extends GetCredentialException {
    public GetCredentialCancellationException() {
        this(null);
    }

    public GetCredentialCancellationException(CharSequence charSequence) {
        super(charSequence, "android.credentials.GetCredentialException.TYPE_USER_CANCELED");
    }
}
