package com.quizlet.remote.model.login;

import com.airbnb.lottie.parser.moshi.c;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.internal.b;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ValidateEmailJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public ValidateEmailJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("address", "isValid", "didYouMean", "isDisposable", "existingAccount");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "address");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Boolean.TYPE, m, "isValid");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Boolean bool = null;
        Boolean bool2 = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 != 0) {
                    l lVar2 = this.c;
                    if (iK0 == 1) {
                        bool = (Boolean) lVar2.a(reader);
                        if (bool == null) {
                            throw b.k("isValid", "isValid", reader);
                        }
                    } else if (iK0 == 2) {
                        str2 = (String) lVar.a(reader);
                    } else if (iK0 == 3) {
                        bool2 = (Boolean) lVar2.a(reader);
                        if (bool2 == null) {
                            throw b.k("isDisposable", "isDisposable", reader);
                        }
                    } else if (iK0 == 4) {
                        str3 = (String) lVar.a(reader);
                    }
                } else {
                    str = (String) lVar.a(reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        Boolean bool3 = bool2;
        if (bool == null) {
            throw b.e("isValid", "isValid", reader);
        }
        boolean zBooleanValue = bool.booleanValue();
        if (bool3 != null) {
            return new ValidateEmail(str, zBooleanValue, str2, bool3.booleanValue(), str3);
        }
        throw b.e("isDisposable", "isDisposable", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        ValidateEmail validateEmail = (ValidateEmail) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (validateEmail == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("address");
        l lVar = this.b;
        lVar.g(writer, validateEmail.a);
        writer.l("isValid");
        Boolean boolValueOf = Boolean.valueOf(validateEmail.b);
        l lVar2 = this.c;
        lVar2.g(writer, boolValueOf);
        writer.l("didYouMean");
        lVar.g(writer, validateEmail.c);
        writer.l("isDisposable");
        Z.q(validateEmail.d, lVar2, writer, "existingAccount");
        lVar.g(writer, validateEmail.e);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(35, "GeneratedJsonAdapter(ValidateEmail)", "toString(...)");
    }
}
