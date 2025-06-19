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
public final class RemoteEntitlementDataJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;

    public RemoteEntitlementDataJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("canUseFeature", "overrideReason", "meteringMeta", "premiumFeatureIdentifier");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Boolean.TYPE, m, "canUseFeature");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "overrideReason");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(RemoteMeteringMeta.class, m, "meteringMeta");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Boolean bool = null;
        String str = null;
        RemoteMeteringMeta remoteMeteringMeta = null;
        String str2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 != 0) {
                l lVar = this.c;
                if (iK0 == 1) {
                    str = (String) lVar.a(reader);
                } else if (iK0 == 2) {
                    remoteMeteringMeta = (RemoteMeteringMeta) this.d.a(reader);
                } else if (iK0 == 3) {
                    str2 = (String) lVar.a(reader);
                }
            } else {
                bool = (Boolean) this.b.a(reader);
                if (bool == null) {
                    throw b.k("canUseFeature", "canUseFeature", reader);
                }
            }
        }
        reader.i();
        if (bool != null) {
            return new RemoteEntitlementData(bool.booleanValue(), str, remoteMeteringMeta, str2);
        }
        throw b.e("canUseFeature", "canUseFeature", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteEntitlementData remoteEntitlementData = (RemoteEntitlementData) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteEntitlementData == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("canUseFeature");
        this.b.g(writer, Boolean.valueOf(remoteEntitlementData.a));
        writer.l("overrideReason");
        l lVar = this.c;
        lVar.g(writer, remoteEntitlementData.b);
        writer.l("meteringMeta");
        this.d.g(writer, remoteEntitlementData.c);
        writer.l("premiumFeatureIdentifier");
        lVar.g(writer, remoteEntitlementData.d);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(43, "GeneratedJsonAdapter(RemoteEntitlementData)", "toString(...)");
    }
}
