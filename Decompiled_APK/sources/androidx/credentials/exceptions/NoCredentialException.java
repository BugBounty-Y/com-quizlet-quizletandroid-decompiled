package androidx.credentials.exceptions;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class NoCredentialException extends GetCredentialException {
    public NoCredentialException() {
        this(null);
    }

    public NoCredentialException(CharSequence charSequence) {
        super(charSequence, "android.credentials.GetCredentialException.TYPE_NO_CREDENTIAL");
    }
}
