package com.quizlet.remote.model.login.magiclink;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.login.magiclink.SendMagicLinkResponse;
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
public final class SendMagicLinkResponseJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public volatile Constructor d;

    public SendMagicLinkResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("success", "errors");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Boolean.TYPE, m, "success");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(SendMagicLinkResponse.Errors.class, m, "errors");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        Boolean bool = Boolean.FALSE;
        reader.d();
        SendMagicLinkResponse.Errors errors = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                bool = (Boolean) this.b.a(reader);
                if (bool == null) {
                    throw com.squareup.moshi.internal.b.k("success", "success", reader);
                }
                i &= -2;
            } else if (iK0 == 1) {
                errors = (SendMagicLinkResponse.Errors) this.c.a(reader);
                i &= -3;
            }
        }
        reader.i();
        if (i == -4) {
            return new SendMagicLinkResponse(bool.booleanValue(), errors);
        }
        Constructor declaredConstructor = this.d;
        if (declaredConstructor == null) {
            declaredConstructor = SendMagicLinkResponse.class.getDeclaredConstructor(Boolean.TYPE, SendMagicLinkResponse.Errors.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.d = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(bool, errors, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (SendMagicLinkResponse) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SendMagicLinkResponse sendMagicLinkResponse = (SendMagicLinkResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (sendMagicLinkResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("success");
        this.b.g(writer, Boolean.valueOf(sendMagicLinkResponse.a));
        writer.l("errors");
        this.c.g(writer, sendMagicLinkResponse.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(43, "GeneratedJsonAdapter(SendMagicLinkResponse)", "toString(...)");
    }
}
