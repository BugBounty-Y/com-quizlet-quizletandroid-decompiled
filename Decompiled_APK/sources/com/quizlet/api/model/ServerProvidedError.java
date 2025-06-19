package com.quizlet.api.model;

import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public interface ServerProvidedError {
    String getIdentifier();

    String getServerMessage();
}
