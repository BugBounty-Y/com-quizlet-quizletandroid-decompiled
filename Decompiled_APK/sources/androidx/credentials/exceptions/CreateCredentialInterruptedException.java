package androidx.credentials.exceptions;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class CreateCredentialInterruptedException extends CreateCredentialException {
    public CreateCredentialInterruptedException() {
        super(null, "android.credentials.CreateCredentialException.TYPE_INTERRUPTED");
    }
}
