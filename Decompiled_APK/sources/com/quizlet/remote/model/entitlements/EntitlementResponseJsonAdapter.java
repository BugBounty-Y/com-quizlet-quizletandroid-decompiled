package com.quizlet.remote.model.entitlements;

import com.airbnb.lottie.parser.moshi.c;
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
public final class EntitlementResponseJsonAdapter extends l {
    public final c a;
    public final l b;

    public EntitlementResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("models");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(RemoteEntitlementModels.class, M.a, "models");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        RemoteEntitlementModels remoteEntitlementModels = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (remoteEntitlementModels = (RemoteEntitlementModels) this.b.a(reader)) == null) {
                throw b.k("models", "models", reader);
            }
        }
        reader.i();
        if (remoteEntitlementModels != null) {
            return new EntitlementResponse(remoteEntitlementModels);
        }
        throw b.e("models", "models", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        EntitlementResponse entitlementResponse = (EntitlementResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (entitlementResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("models");
        this.b.g(writer, entitlementResponse.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(41, "GeneratedJsonAdapter(EntitlementResponse)", "toString(...)");
    }
}
