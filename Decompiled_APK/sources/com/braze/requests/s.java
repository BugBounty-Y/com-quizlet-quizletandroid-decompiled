package com.braze.requests;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class s implements o {
    public final com.braze.requests.util.c a;

    public s(com.braze.requests.util.c requestTarget) {
        Intrinsics.checkNotNullParameter(requestTarget, "requestTarget");
        this.a = requestTarget;
    }
}
