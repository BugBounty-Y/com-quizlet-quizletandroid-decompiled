package com.quizlet.remote.model.search;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
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
public final class SearchBannerWrapperJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public volatile Constructor c;

    public SearchBannerWrapperJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("icon", "name", DBUserFields.Names.USER_UPGRADE_TYPE, DTBMetricsConfiguration.APSMETRICS_URL);
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(String.class, M.a, "icon");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
                i &= -2;
            } else if (iK0 == 1) {
                str2 = (String) this.b.a(reader);
                i &= -3;
            } else if (iK0 == 2) {
                str3 = (String) this.b.a(reader);
                i &= -5;
            } else if (iK0 == 3) {
                str4 = (String) this.b.a(reader);
                i &= -9;
            }
        }
        reader.i();
        if (i == -16) {
            return new SearchBannerWrapper(str, str2, str3, str4);
        }
        Constructor declaredConstructor = this.c;
        if (declaredConstructor == null) {
            declaredConstructor = SearchBannerWrapper.class.getDeclaredConstructor(String.class, String.class, String.class, String.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.c = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(str, str2, str3, str4, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (SearchBannerWrapper) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SearchBannerWrapper searchBannerWrapper = (SearchBannerWrapper) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (searchBannerWrapper == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("icon");
        l lVar = this.b;
        lVar.g(writer, searchBannerWrapper.a);
        writer.l("name");
        lVar.g(writer, searchBannerWrapper.b);
        writer.l(DBUserFields.Names.USER_UPGRADE_TYPE);
        lVar.g(writer, searchBannerWrapper.c);
        writer.l(DTBMetricsConfiguration.APSMETRICS_URL);
        lVar.g(writer, searchBannerWrapper.d);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(41, "GeneratedJsonAdapter(SearchBannerWrapper)", "toString(...)");
    }
}
