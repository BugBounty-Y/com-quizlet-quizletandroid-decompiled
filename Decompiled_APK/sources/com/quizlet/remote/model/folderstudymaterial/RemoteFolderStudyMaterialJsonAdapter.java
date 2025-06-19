package com.quizlet.remote.model.folderstudymaterial;

import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
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
public final class RemoteFolderStudyMaterialJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public volatile Constructor f;

    public RemoteFolderStudyMaterialJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "folderId", "studyMaterialId", "studyMaterialType", "userId", "subFolderId", "timestamp", "lastModified", "isDeleted");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.class, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(String.class, m, "studyMaterialId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(Integer.class, m, "studyMaterialType");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(Boolean.class, m, "isDeleted");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        int i = -1;
        Long l = null;
        Long l2 = null;
        String str = null;
        Integer num = null;
        Long l3 = null;
        Long l4 = null;
        Long l5 = null;
        Long l6 = null;
        Boolean bool = null;
        while (reader.l()) {
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    l = (Long) this.b.a(reader);
                    break;
                case 1:
                    l2 = (Long) this.b.a(reader);
                    break;
                case 2:
                    str = (String) this.c.a(reader);
                    break;
                case 3:
                    num = (Integer) this.d.a(reader);
                    break;
                case 4:
                    l3 = (Long) this.b.a(reader);
                    break;
                case 5:
                    l4 = (Long) this.b.a(reader);
                    break;
                case 6:
                    l5 = (Long) this.b.a(reader);
                    break;
                case 7:
                    l6 = (Long) this.b.a(reader);
                    break;
                case 8:
                    bool = (Boolean) this.e.a(reader);
                    i = -257;
                    break;
            }
        }
        reader.i();
        if (i == -257) {
            Boolean bool2 = bool;
            Long l7 = l6;
            Long l8 = l5;
            Long l9 = l4;
            Long l10 = l3;
            Integer num2 = num;
            return new RemoteFolderStudyMaterial(l, l2, str, num2, l10, l9, l8, l7, bool2);
        }
        Boolean bool3 = bool;
        Long l11 = l6;
        Long l12 = l5;
        Long l13 = l4;
        Long l14 = l3;
        Integer num3 = num;
        String str2 = str;
        Long l15 = l2;
        Long l16 = l;
        Constructor declaredConstructor = this.f;
        if (declaredConstructor == null) {
            declaredConstructor = RemoteFolderStudyMaterial.class.getDeclaredConstructor(Long.class, Long.class, String.class, Integer.class, Long.class, Long.class, Long.class, Long.class, Boolean.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.f = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(l16, l15, str2, num3, l14, l13, l12, l11, bool3, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteFolderStudyMaterial) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteFolderStudyMaterial remoteFolderStudyMaterial = (RemoteFolderStudyMaterial) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteFolderStudyMaterial == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        com.squareup.moshi.l lVar = this.b;
        lVar.g(writer, remoteFolderStudyMaterial.a);
        writer.l("folderId");
        lVar.g(writer, remoteFolderStudyMaterial.b);
        writer.l("studyMaterialId");
        this.c.g(writer, remoteFolderStudyMaterial.c);
        writer.l("studyMaterialType");
        this.d.g(writer, remoteFolderStudyMaterial.d);
        writer.l("userId");
        lVar.g(writer, remoteFolderStudyMaterial.e);
        writer.l("subFolderId");
        lVar.g(writer, remoteFolderStudyMaterial.f);
        writer.l("timestamp");
        lVar.g(writer, remoteFolderStudyMaterial.g);
        writer.l("lastModified");
        lVar.g(writer, remoteFolderStudyMaterial.h);
        writer.l("isDeleted");
        this.e.g(writer, remoteFolderStudyMaterial.i);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(47, "GeneratedJsonAdapter(RemoteFolderStudyMaterial)", "toString(...)");
    }
}
