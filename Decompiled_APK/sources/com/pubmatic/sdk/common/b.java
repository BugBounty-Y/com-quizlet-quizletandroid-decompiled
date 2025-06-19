package com.pubmatic.sdk.common;

import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class b {

    @NotNull
    private final String a;

    @NotNull
    private final List<Integer> b;

    public /* synthetic */ b(String str, List list, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, list);
    }

    @NotNull
    public final List<Integer> getProfileIds() {
        return this.b;
    }

    @NotNull
    public final String getPublisherId() {
        return this.a;
    }

    private b(String str, List<Integer> list) {
        this.a = str;
        this.b = list;
    }
}
