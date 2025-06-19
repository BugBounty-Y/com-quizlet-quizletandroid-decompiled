package androidx.credentials.exceptions;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class CreateCredentialCancellationException extends CreateCredentialException {
    public CreateCredentialCancellationException() {
        super(null, "android.credentials.CreateCredentialException.TYPE_USER_CANCELED");
    }
}
