package com.quizlet.remote.model.explanations.question;

import com.quizlet.remote.model.explanations.RemoteSimpleImage;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteQuestionPrompt {
    public final String a;
    public final RemoteSimpleImage b;

    public RemoteQuestionPrompt(@InterfaceC4853h(name = "text") String str, @InterfaceC4853h(name = "image") RemoteSimpleImage remoteSimpleImage) {
        this.a = str;
        this.b = remoteSimpleImage;
    }
}
