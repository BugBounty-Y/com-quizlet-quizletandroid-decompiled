package com.quizlet.remote.model.explanations.solution;

import com.quizlet.remote.model.explanations.RemoteSimpleImage;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSolutionColumnImage {
    public final RemoteSimpleImage a;
    public final RemoteSimpleImage b;

    public RemoteSolutionColumnImage(@InterfaceC4853h(name = "large") RemoteSimpleImage remoteSimpleImage, @InterfaceC4853h(name = "regular") RemoteSimpleImage remoteSimpleImage2) {
        this.a = remoteSimpleImage;
        this.b = remoteSimpleImage2;
    }

    public /* synthetic */ RemoteSolutionColumnImage(RemoteSimpleImage remoteSimpleImage, RemoteSimpleImage remoteSimpleImage2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : remoteSimpleImage, remoteSimpleImage2);
    }
}
