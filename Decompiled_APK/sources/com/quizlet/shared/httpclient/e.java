package com.quizlet.shared.httpclient;

import com.google.android.gms.internal.mlkit_vision_barcode.R4;
import java.util.Map;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends R4 {
    public final String a;
    public final Map b;
    public final String c;
    public final d d;

    public e(String url, Map queryParameters, String str, d method) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(queryParameters, "queryParameters");
        Intrinsics.checkNotNullParameter(method, "method");
        this.a = url;
        this.b = queryParameters;
        this.c = str;
        this.d = method;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.R4
    public final String c() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b) && Intrinsics.b(this.c, eVar.c) && this.d == eVar.d;
    }

    public final int hashCode() {
        int iD = assistantMode.refactored.a.d(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        return this.d.hashCode() + ((iD + (str == null ? 0 : str.hashCode())) * 31);
    }

    public final String toString() {
        return "Request(url=" + this.a + ", queryParameters=" + this.b + ", body=" + this.c + ", method=" + this.d + ")";
    }

    public /* synthetic */ e(String str, Map map, String str2, d dVar, int i) {
        this(str, (i & 2) != 0 ? V.c() : map, (i & 4) != 0 ? null : str2, dVar);
    }
}
