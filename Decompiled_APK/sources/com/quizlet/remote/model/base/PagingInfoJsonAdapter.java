package com.quizlet.remote.model.base;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class PagingInfoJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public volatile Constructor d;

    public PagingInfoJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("total", "page", "token", "perPage");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Integer.TYPE, m, "total");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "pagingToken");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Integer num = 0;
        Integer num2 = null;
        Integer num3 = null;
        String str = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                num = (Integer) this.b.a(reader);
                if (num == null) {
                    throw com.squareup.moshi.internal.b.k("total", "total", reader);
                }
                i &= -2;
            } else if (iK0 == 1) {
                num2 = (Integer) this.b.a(reader);
                if (num2 == null) {
                    throw com.squareup.moshi.internal.b.k("page", "page", reader);
                }
                i &= -3;
            } else if (iK0 == 2) {
                str = (String) this.c.a(reader);
                i &= -5;
            } else if (iK0 == 3) {
                num3 = (Integer) this.b.a(reader);
                if (num3 == null) {
                    throw com.squareup.moshi.internal.b.k("perPage", "perPage", reader);
                }
                i &= -9;
            } else {
                continue;
            }
        }
        reader.i();
        if (i == -16) {
            return new PagingInfo(num.intValue(), num2.intValue(), str, num3.intValue());
        }
        Constructor declaredConstructor = this.d;
        if (declaredConstructor == null) {
            Class cls = com.squareup.moshi.internal.b.c;
            Class cls2 = Integer.TYPE;
            declaredConstructor = PagingInfo.class.getDeclaredConstructor(cls2, cls2, String.class, cls2, cls2, cls);
            this.d = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(num, num2, str, num3, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (PagingInfo) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        PagingInfo pagingInfo = (PagingInfo) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (pagingInfo == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("total");
        Integer numValueOf = Integer.valueOf(pagingInfo.a);
        l lVar = this.b;
        lVar.g(writer, numValueOf);
        writer.l("page");
        AbstractC4178x.p(pagingInfo.b, lVar, writer, "token");
        this.c.g(writer, pagingInfo.c);
        writer.l("perPage");
        lVar.g(writer, Integer.valueOf(pagingInfo.d));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(32, "GeneratedJsonAdapter(PagingInfo)", "toString(...)");
    }
}
