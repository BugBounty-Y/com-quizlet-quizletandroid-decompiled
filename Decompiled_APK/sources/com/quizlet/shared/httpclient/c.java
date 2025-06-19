package com.quizlet.shared.httpclient;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.mlkit_vision_barcode.R4;
import java.util.ArrayList;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends R4 {
    public final String a;
    public final Map b;
    public final ArrayList c;

    public c(String url, Map queryParameters, ArrayList files) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(queryParameters, "queryParameters");
        Intrinsics.checkNotNullParameter(files, "files");
        this.a = url;
        this.b = queryParameters;
        this.c = files;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.R4
    public final String c() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Intrinsics.b(this.b, cVar.b) && Intrinsics.b(this.c, cVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + assistantMode.refactored.a.d(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MultipartRequest(url=");
        sb.append(this.a);
        sb.append(", queryParameters=");
        sb.append(this.b);
        sb.append(", files=");
        return AbstractC0147y.f(")", sb, this.c);
    }
}
