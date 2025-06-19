package androidx.credentials.exceptions;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class ClearCredentialUnsupportedException extends ClearCredentialException {
    public ClearCredentialUnsupportedException() {
        this(null);
    }

    public ClearCredentialUnsupportedException(String str) {
        super("androidx.credentials.TYPE_CLEAR_CREDENTIAL_UNSUPPORTED_EXCEPTION", str);
    }
}
