package com.snowplowanalytics.core.screenviews;

import com.snowplowanalytics.core.statemachine.d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements d {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final a f;

    public a(String name, String str, String id, String str2, String str3, a aVar) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(id, "id");
        this.a = name;
        this.b = str;
        this.c = id;
        this.d = str2;
        this.e = str3;
        this.f = aVar;
    }
}
