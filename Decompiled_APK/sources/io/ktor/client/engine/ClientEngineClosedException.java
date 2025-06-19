package io.ktor.client.engine;

import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class ClientEngineClosedException extends IllegalStateException {
    public ClientEngineClosedException() {
        this(0);
    }

    @Override // java.lang.Throwable
    public final Throwable getCause() {
        return null;
    }

    public ClientEngineClosedException(int i) {
        super("Client already closed");
    }
}
