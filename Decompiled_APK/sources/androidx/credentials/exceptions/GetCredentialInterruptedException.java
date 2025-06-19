package androidx.credentials.exceptions;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class GetCredentialInterruptedException extends GetCredentialException {
    public GetCredentialInterruptedException() {
        this(null);
    }

    public GetCredentialInterruptedException(CharSequence charSequence) {
        super(charSequence, "android.credentials.GetCredentialException.TYPE_INTERRUPTED");
    }
}
