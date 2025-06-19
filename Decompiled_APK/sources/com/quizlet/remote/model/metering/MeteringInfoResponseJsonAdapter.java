package com.quizlet.remote.model.metering;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.base.ModelError;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.base.ValidationError;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
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
public final class MeteringInfoResponseJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;

    public MeteringInfoResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("data", "reason", "paging", "validationErrors", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(RemoteMeteringInfo.class, m, "data");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.class, m, "reason");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(PagingInfo.class, m, "pagingInfo");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(H.f(List.class, ValidationError.class), m, "validationErrors");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(ModelError.class, m, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        RemoteMeteringInfo remoteMeteringInfo = null;
        PagingInfo pagingInfo = null;
        List list = null;
        ModelError modelError = null;
        boolean z = false;
        boolean z2 = false;
        boolean z3 = false;
        Integer num = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                remoteMeteringInfo = (RemoteMeteringInfo) this.b.a(reader);
            } else if (iK0 == 1) {
                num = (Integer) this.c.a(reader);
            } else if (iK0 == 2) {
                pagingInfo = (PagingInfo) this.d.a(reader);
                z = true;
            } else if (iK0 == 3) {
                list = (List) this.e.a(reader);
                z2 = true;
            } else if (iK0 == 4) {
                modelError = (ModelError) this.f.a(reader);
                z3 = true;
            }
        }
        reader.i();
        MeteringInfoResponse meteringInfoResponse = new MeteringInfoResponse(remoteMeteringInfo, num);
        if (z) {
            meteringInfoResponse.a = pagingInfo;
        }
        if (z2) {
            meteringInfoResponse.b = list;
        }
        if (z3) {
            meteringInfoResponse.c = modelError;
        }
        return meteringInfoResponse;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        MeteringInfoResponse meteringInfoResponse = (MeteringInfoResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (meteringInfoResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("data");
        this.b.g(writer, meteringInfoResponse.d);
        writer.l("reason");
        this.c.g(writer, meteringInfoResponse.e);
        writer.l("paging");
        this.d.g(writer, meteringInfoResponse.a);
        writer.l("validationErrors");
        this.e.g(writer, meteringInfoResponse.b);
        writer.l("error");
        this.f.g(writer, meteringInfoResponse.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(42, "GeneratedJsonAdapter(MeteringInfoResponse)", "toString(...)");
    }
}
