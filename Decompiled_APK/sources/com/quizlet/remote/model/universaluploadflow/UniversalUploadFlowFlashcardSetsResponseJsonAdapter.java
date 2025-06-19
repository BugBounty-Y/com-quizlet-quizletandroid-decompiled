package com.quizlet.remote.model.universaluploadflow;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.classset.RemoteClassSet;
import com.quizlet.remote.model.session.RemoteSession;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class UniversalUploadFlowFlashcardSetsResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public volatile Constructor f;

    public UniversalUploadFlowFlashcardSetsResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("classSet", "set", "session", "user");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteClassSet.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "classSet");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteSet.class), m, "set");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, RemoteSession.class), m, "session");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(H.f(List.class, RemoteUser.class), m, "user");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        List list2 = null;
        List list3 = null;
        List list4 = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                if (list == null) {
                    throw com.squareup.moshi.internal.b.k("classSet", "classSet", reader);
                }
                i &= -2;
            } else if (iK0 == 1) {
                list2 = (List) this.c.a(reader);
                if (list2 == null) {
                    throw com.squareup.moshi.internal.b.k("set_", "set", reader);
                }
                i &= -3;
            } else if (iK0 == 2) {
                list3 = (List) this.d.a(reader);
                if (list3 == null) {
                    throw com.squareup.moshi.internal.b.k("session", "session", reader);
                }
                i &= -5;
            } else if (iK0 == 3) {
                list4 = (List) this.e.a(reader);
                i &= -9;
            }
        }
        reader.i();
        if (i == -16) {
            Intrinsics.e(list, "null cannot be cast to non-null type kotlin.collections.List<com.quizlet.remote.model.classset.RemoteClassSet>");
            Intrinsics.e(list2, "null cannot be cast to non-null type kotlin.collections.List<com.quizlet.remote.model.set.RemoteSet>");
            Intrinsics.e(list3, "null cannot be cast to non-null type kotlin.collections.List<com.quizlet.remote.model.session.RemoteSession>");
            return new UniversalUploadFlowFlashcardSetsResponse(list, list2, list3, list4);
        }
        Constructor declaredConstructor = this.f;
        if (declaredConstructor == null) {
            declaredConstructor = UniversalUploadFlowFlashcardSetsResponse.class.getDeclaredConstructor(List.class, List.class, List.class, List.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.f = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(list, list2, list3, list4, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (UniversalUploadFlowFlashcardSetsResponse) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        UniversalUploadFlowFlashcardSetsResponse universalUploadFlowFlashcardSetsResponse = (UniversalUploadFlowFlashcardSetsResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (universalUploadFlowFlashcardSetsResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("classSet");
        this.b.g(writer, universalUploadFlowFlashcardSetsResponse.a);
        writer.l("set");
        this.c.g(writer, universalUploadFlowFlashcardSetsResponse.b);
        writer.l("session");
        this.d.g(writer, universalUploadFlowFlashcardSetsResponse.c);
        writer.l("user");
        this.e.g(writer, universalUploadFlowFlashcardSetsResponse.d);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(62, "GeneratedJsonAdapter(UniversalUploadFlowFlashcardSetsResponse)", "toString(...)");
    }
}
