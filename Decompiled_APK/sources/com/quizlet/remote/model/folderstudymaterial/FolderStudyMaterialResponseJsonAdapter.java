package com.quizlet.remote.model.folderstudymaterial;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.base.ModelError;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.base.ValidationError;
import com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialResponse;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FolderStudyMaterialResponseJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public volatile Constructor f;

    public FolderStudyMaterialResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("models", "paging", "validationErrors", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        com.squareup.moshi.l lVarA = moshi.a(FolderStudyMaterialResponse.Models.class, m, "models");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(PagingInfo.class, m, "pagingInfo");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(H.f(List.class, ValidationError.class), m, "validationErrors");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(ModelError.class, m, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws NoSuchMethodException, SecurityException {
        FolderStudyMaterialResponse folderStudyMaterialResponse;
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        boolean z = false;
        FolderStudyMaterialResponse.Models models = null;
        PagingInfo pagingInfo = null;
        List list = null;
        ModelError modelError = null;
        boolean z2 = false;
        boolean z3 = false;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                models = (FolderStudyMaterialResponse.Models) this.b.a(reader);
                i = -2;
            } else if (iK0 == 1) {
                pagingInfo = (PagingInfo) this.c.a(reader);
                z = true;
            } else if (iK0 == 2) {
                list = (List) this.d.a(reader);
                z2 = true;
            } else if (iK0 == 3) {
                modelError = (ModelError) this.e.a(reader);
                z3 = true;
            }
        }
        reader.i();
        if (i == -2) {
            folderStudyMaterialResponse = new FolderStudyMaterialResponse(models);
        } else {
            Constructor declaredConstructor = this.f;
            if (declaredConstructor == null) {
                declaredConstructor = FolderStudyMaterialResponse.class.getDeclaredConstructor(FolderStudyMaterialResponse.Models.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
                this.f = declaredConstructor;
                Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
            }
            folderStudyMaterialResponse = (FolderStudyMaterialResponse) declaredConstructor.newInstance(models, Integer.valueOf(i), null);
        }
        if (z) {
            folderStudyMaterialResponse.a = pagingInfo;
        }
        if (z2) {
            folderStudyMaterialResponse.b = list;
        }
        if (z3) {
            folderStudyMaterialResponse.c = modelError;
        }
        return folderStudyMaterialResponse;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        FolderStudyMaterialResponse folderStudyMaterialResponse = (FolderStudyMaterialResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (folderStudyMaterialResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("models");
        this.b.g(writer, folderStudyMaterialResponse.d);
        writer.l("paging");
        this.c.g(writer, folderStudyMaterialResponse.a);
        writer.l("validationErrors");
        this.d.g(writer, folderStudyMaterialResponse.b);
        writer.l("error");
        this.e.g(writer, folderStudyMaterialResponse.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(49, "GeneratedJsonAdapter(FolderStudyMaterialResponse)", "toString(...)");
    }
}
