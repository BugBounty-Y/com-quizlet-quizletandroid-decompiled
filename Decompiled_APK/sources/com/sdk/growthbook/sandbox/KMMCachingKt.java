package com.sdk.growthbook.sandbox;

import androidx.navigation.F;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.json.b;
import kotlinx.serialization.json.c;
import kotlinx.serialization.json.internal.n;
import kotlinx.serialization.json.k;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class KMMCachingKt {
    public static final <T> T getData(@NotNull CachingLayer cachingLayer, @NotNull String fileName, @NotNull KSerializer serializer) {
        Intrinsics.checkNotNullParameter(cachingLayer, "<this>");
        Intrinsics.checkNotNullParameter(fileName, "fileName");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        k content = cachingLayer.getContent(fileName);
        if (content == null) {
            return null;
        }
        return (T) c.d.a(serializer, content);
    }

    public static final <T> void putData(@NotNull CachingLayer cachingLayer, @NotNull String fileName, T t, @NotNull KSerializer serializer) {
        Intrinsics.checkNotNullParameter(cachingLayer, "<this>");
        Intrinsics.checkNotNullParameter(fileName, "fileName");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        b json = c.d;
        json.getClass();
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        J j = new J();
        new n(json, new F(j, 1), 1).y(serializer, t);
        Object obj = j.a;
        if (obj != null) {
            cachingLayer.saveContent(fileName, (k) obj);
        } else {
            Intrinsics.m("result");
            throw null;
        }
    }
}
