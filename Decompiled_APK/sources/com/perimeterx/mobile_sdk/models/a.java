package com.perimeterx.mobile_sdk.models;

import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final String a;
    public final String b;
    public final ArrayList c;

    public a(String userId, String str, ArrayList arrayList) {
        Intrinsics.checkNotNullParameter(userId, "userId");
        this.a = userId;
        this.b = str;
        this.c = arrayList;
    }
}
