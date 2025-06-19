package com.quizlet.remote.model.explanations.search;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSearchResultQuestion implements b {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final List e;
    public final long f;
    public final String g;
    public final String h;

    public RemoteSearchResultQuestion(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "prompt") @NotNull String prompt, @InterfaceC4853h(name = "clarification") String str, @InterfaceC4853h(name = "slug") @NotNull String slug, @InterfaceC4853h(name = "subjectIds") @NotNull List<Integer> subjectIds, @InterfaceC4853h(name = "createdTimestamp") long j2, @InterfaceC4853h(name = "_humanized") String str2, @InterfaceC4853h(name = "_webUrl") String str3) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(slug, "slug");
        Intrinsics.checkNotNullParameter(subjectIds, "subjectIds");
        this.a = j;
        this.b = prompt;
        this.c = str;
        this.d = slug;
        this.e = subjectIds;
        this.f = j2;
        this.g = str2;
        this.h = str3;
    }
}
