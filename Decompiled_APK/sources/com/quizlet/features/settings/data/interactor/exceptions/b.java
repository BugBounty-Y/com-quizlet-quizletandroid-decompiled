package com.quizlet.features.settings.data.interactor.exceptions;

import com.quizlet.api.model.ServerProvidedError;

/* loaded from: classes3.dex */
public final class b implements ServerProvidedError {
    public static final b a = new b();

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof b);
    }

    @Override // com.quizlet.api.model.ServerProvidedError
    public final String getIdentifier() {
        return null;
    }

    @Override // com.quizlet.api.model.ServerProvidedError
    public final String getServerMessage() {
        return null;
    }

    public final int hashCode() {
        return -2068703550;
    }

    public final String toString() {
        return "UnknownServerProvidedError";
    }
}
