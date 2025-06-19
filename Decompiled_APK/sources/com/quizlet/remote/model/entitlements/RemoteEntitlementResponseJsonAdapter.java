package com.quizlet.remote.model.entitlements;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.b;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteEntitlementResponseJsonAdapter extends l {
    public final c a;
    public final l b;

    public RemoteEntitlementResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("responses");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(H.f(List.class, EntitlementResponse.class), M.a, "responses");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (list = (List) this.b.a(reader)) == null) {
                throw b.k("responses", "responses", reader);
            }
        }
        reader.i();
        if (list != null) {
            return new RemoteEntitlementResponse(list);
        }
        throw b.e("responses", "responses", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteEntitlementResponse remoteEntitlementResponse = (RemoteEntitlementResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteEntitlementResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("responses");
        this.b.g(writer, remoteEntitlementResponse.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(47, "GeneratedJsonAdapter(RemoteEntitlementResponse)", "toString(...)");
    }
}
