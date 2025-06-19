package com.quizlet.remote.model.explanations.solution;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSolutionColumnImages {
    public final RemoteSolutionColumnImage a;
    public final RemoteSolutionColumnImage b;

    public RemoteSolutionColumnImages(@InterfaceC4853h(name = "latex") RemoteSolutionColumnImage remoteSolutionColumnImage, @InterfaceC4853h(name = "additional") RemoteSolutionColumnImage remoteSolutionColumnImage2) {
        this.a = remoteSolutionColumnImage;
        this.b = remoteSolutionColumnImage2;
    }
}
