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
public final class SendMagicLinkResponse_ErrorsJsonAdapter extends l {
    public final c a;
    public final l b;
    public volatile Constructor c;

    public SendMagicLinkResponse_ErrorsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("email", "generic");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(String.class, M.a, "email");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
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
            }
        }
        reader.i();
        if (i == -4) {
            return new SendMagicLinkResponse.Errors(str, str2);
        }
        Constructor declaredConstructor = this.c;
        if (declaredConstructor == null) {
            declaredConstructor = SendMagicLinkResponse.Errors.class.getDeclaredConstructor(String.class, String.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.c = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(str, str2, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (SendMagicLinkResponse.Errors) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SendMagicLinkResponse.Errors errors = (SendMagicLinkResponse.Errors) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (errors == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("email");
        l lVar = this.b;
        lVar.g(writer, errors.a);
        writer.l("generic");
        lVar.g(writer, errors.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(50, "GeneratedJsonAdapter(SendMagicLinkResponse.Errors)", "toString(...)");
    }
}
