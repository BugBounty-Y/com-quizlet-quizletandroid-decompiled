package io.ktor.client.request;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3171i7;
import io.ktor.http.l;
import io.ktor.http.p;
import io.ktor.http.u;
import io.ktor.http.w;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.A0;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class c {
    public final w a = new w();
    public p b = p.b;
    public final l c = new l(13);
    public Object d = io.ktor.client.utils.b.a;
    public A0 e = E.e();
    public final io.ktor.util.e f = new io.ktor.util.e();

    public final void a(io.ktor.util.reflect.a aVar) {
        io.ktor.util.e eVar = this.f;
        if (aVar != null) {
            eVar.e(i.a, aVar);
            return;
        }
        io.ktor.util.a key = i.a;
        eVar.getClass();
        Intrinsics.checkNotNullParameter(key, "key");
        eVar.c().remove(key);
    }

    public final void b(c builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        this.b = builder.b;
        this.d = builder.d;
        io.ktor.util.a aVar = i.a;
        io.ktor.util.e other = builder.f;
        a((io.ktor.util.reflect.a) other.d(aVar));
        w wVar = this.a;
        Intrinsics.checkNotNullParameter(wVar, "<this>");
        w url = builder.a;
        Intrinsics.checkNotNullParameter(url, "url");
        wVar.d = url.d;
        wVar.d(url.a);
        wVar.e(url.c);
        List list = url.h;
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        wVar.h = list;
        wVar.e = url.e;
        wVar.f = url.f;
        u value = new u(13);
        AbstractC3171i7.e(value, url.i);
        Intrinsics.checkNotNullParameter(value, "value");
        wVar.i = value;
        wVar.j = new com.quizlet.login.common.interactors.d(value);
        String str = url.g;
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        wVar.g = str;
        wVar.b = url.b;
        List list2 = wVar.h;
        Intrinsics.checkNotNullParameter(list2, "<set-?>");
        wVar.h = list2;
        AbstractC3171i7.e(this.c, builder.c);
        io.ktor.util.e eVar = this.f;
        Intrinsics.checkNotNullParameter(eVar, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        for (io.ktor.util.a aVar2 : CollectionsKt.w0(other.c().keySet())) {
            Intrinsics.e(aVar2, "null cannot be cast to non-null type io.ktor.util.AttributeKey<kotlin.Any>");
            eVar.e(aVar2, other.b(aVar2));
        }
    }
}
