package com.perimeterx.mobile_sdk.models;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d {
    public final String a;
    public final String b;

    public d(String name, String token) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(token, "token");
        this.a = name;
        this.b = token;
    }
}
