package coil3.request;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class NullRequestDataException extends RuntimeException {
    public NullRequestDataException() {
        super("The request's data is null.");
    }
}
